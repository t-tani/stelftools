"""YARA-x scan pipeline for the matcher.

Stages, in the order :func:`stelftools.match.run_one_with_state` calls
them:

1. :func:`compile_yara_file` reads the ``.yara`` source, compiles it via
   yara-x, and caches the compiled blob under
   ``$STELFTOOLS_PATH/.cache/yara/`` so a warm hit deserialises ~8x
   faster than recompiling.
2. :func:`yara_matching` scans the target bytes with those rules and
   returns the matching-rules iterable.
3. :func:`format_match_res` folds yara-x ``Rule`` objects into the
   canonical ``{addr: {names, size, detected, category}}`` shape every
   downstream pass consumes.
4. :func:`marge_nomatch_functions` and :func:`marge_functions` graft
   unmatched call sites and lower-length matches onto that table.

Two helpers (:func:`get_target_fp`, :func:`_get_target_data`) open and
read the target ELF; :func:`get_yara_rule` is the legacy single-length
compile path that yara-aware consumers (plugins/ida.py) still drive.
"""

import json
import os
import re
import sys

import yara_x

from . import (
    MAX_PATTERN_LENGTH,
    STELFTOOLS_PATH,
    _CRT_FINI_LIST,
    _CRT_INIT_LIST,
)


CACHE_DIR = STELFTOOLS_PATH + ".cache/yara/"


def format_match_res(match_res, symtab_info, risc_v_flag):
    # match_res: iterable of yara_x.Rule (ScanResults.matching_rules).
    # The yara-x API replaces yara-python's m.strings[*].instances[*]
    # with rule.patterns[*].matches[*], and m.meta (dict) with
    # rule.metadata (tuple of (name, value) pairs).
    functions = {}
    for m in match_res:
        meta = dict(m.metadata)
        for pattern in m.patterns:
            for match in pattern.matches:
                addr = match.offset
                # match.length is the real matched span; the historical
                # yara-python code overrode it with meta['size'] whenever
                # max_match_data capped the reported length. Keep the
                # semantic so signature-length-based heuristics downstream
                # (del_mismatch, marge_functions) see the rule's declared
                # function size, not the raw scan return.
                if int(meta['size']) > MAX_PATTERN_LENGTH or risc_v_flag == False:
                    matched_len = int(meta['size'])
                for begin, end, vaddr in symtab_info:
                    if begin <= addr < end or begin == end == 0:
                        addr += vaddr
                        # fix risc-v relaxation size
                        if 'hex_only_num' in meta and (matched_len % 4) != 0:
                            matched_len = (matched_len // 4) * 4
                        if addr in functions:
                            # exclude risc-v mismatch many relaxation function
                            if 'hex_only_num' in meta:
                                if matched_len > int(meta['hex_only_num']):
                                    continue
                            if functions[addr]['size'] < matched_len: # overwrite big func info
                                functions[addr]['names'] = [x for x in meta['aliases'].split(', ')]
                                functions[addr]['size'] = matched_len
                                functions[addr]['detected'] = True
                            elif functions[addr]['size'] == matched_len:
                                functions[addr]['names'].extend([x for x in meta['aliases'].split(', ')])
                        else:
                            functions[addr] = { \
                                    'names': [x for x in meta['aliases'].split(', ')], \
                                    'size' : matched_len, \
                                    'detected' : True, \
                                    'category' : 'library function'
                                    }
    return functions


def yara_matching(rules, target):
    data = _get_target_data(target)
    scanner = yara_x.Scanner(rules)
    return scanner.scan(data).matching_rules


def _get_target_data(f):
    f.seek(0)
    return f.read()


def get_target_fp(target_path):
    if not os.path.exists(target_path):
        print('%s : No such target file' % (target_path), file=sys.stderr)
        exit(-1)
    target = open(target_path, 'rb')
    return target


#def marge_nomatch_functions(_functions, call_map, base_vaddr):
def marge_nomatch_functions(_functions, call_map):
    # add addresses to the dict that do not have a pattern match from the function being called
    _exclude_addr_list = []
    for _, _, _c_addr in call_map:
        #call_addr = _c_addr + base_vaddr
        call_addr = _c_addr# + base_vaddr
        if not call_addr in _functions.keys():
            #_functions[call_addr] = {}
            _functions[call_addr] = { \
                    'names': [''], \
                    'size' : 0, \
                    'detected' : True, \
                    'category' : 'unmatch'
                    }
    _func_addr_list = sorted(_functions.keys())
    for _idx, _addr in enumerate(_func_addr_list):
        if _functions[_addr] == {} and _idx != 0:
            _prev_addr = _func_addr_list[_idx-1]
            try:
                if _addr < _prev_addr + _functions[_prev_addr]['size']:
                    _exclude_addr_list.append(_addr)
            except KeyError:
                continue
    # exclude address other than the first address of the function
    for _exclude_addr in _exclude_addr_list:
        del _functions[_exclude_addr]
    return _functions


def marge_functions(functions, _functions):
    _func_addr_list = sorted(functions.keys())
    for _addr in _func_addr_list:
        if functions[_addr]['names'] != ['']:
            continue
        if _addr in _functions.keys():
            functions[_addr] = _functions[_addr]
    return functions


# Todo : fix the hardcode point
def get_yara_rule(yara_rule_path, r_type, r_length):
    risc_v_flag = False

    use_rule_list = []
    all_rule_line = []
    with open(yara_rule_path) as yfp:
        for rule_line in yfp:
            rule_line_fmt = rule_line.replace('\n', '')
            all_rule_line.append(rule_line_fmt)
    rule_version = all_rule_line[0].split(' ')[4]
    if rule_version == '0.2.0_2021_07_29':
        for line_index, yara_rule_line in enumerate(all_rule_line):
            if yara_rule_line.startswith('rule'):
                y_pattern = str(all_rule_line[line_index+7].strip('\t').strip('$pattern = {').strip(' }'))
                # get yara rule real length
                fmt_y_pattern = re.sub(r'(?<=\().*?(?=\))', 'XX', y_pattern).split(' ')
                y_pattern_length = len(fmt_y_pattern) - fmt_y_pattern.count('??') # pattern len - wildcard len
                # get yara rule type
                fmt_r_type = str(all_rule_line[line_index+3].strip('\t').replace('type = \"', '').replace('\"', ''))
                r_func_list = sorted(all_rule_line[line_index+2].strip('\t').split('\"')[1].split(' '))
                #print(r_func_list)
                if fmt_r_type == r_type and y_pattern_length >= r_length \
                        or len(set(_CRT_INIT_LIST + _CRT_FINI_LIST) & set(r_func_list)) > 0:
                    for index in range(11):
                        use_rule_list.append(all_rule_line[line_index+index])
    else: # default yara format
        use_rule_list = all_rule_line
    rule_str = '\n'.join(use_rule_list)
    use_rule_list = yara_x.compile(rule_str)
    return use_rule_list, risc_v_flag


def _parse_rule_lengths(yara_rule_path):
    # Build {rule_identifier: y_pattern_length} by parsing the .yara
    # source once. CRT init/fini rules get a sentinel length large
    # enough that any L >= 1 keeps them, matching the historical
    # `or len(set(_CRT_*) & set(r_func_list)) > 0` clause in
    # get_yara_rule(). Used by run_one() to filter a single compiled
    # rule set per length bucket without re-parsing/recompiling.
    lengths = {}
    with open(yara_rule_path) as fp:
        lines = [line.rstrip('\n') for line in fp]
    if not lines:
        return lengths
    head = lines[0].split(' ')
    rule_version = head[4] if len(head) > 4 else ''
    if rule_version != '0.2.0_2021_07_29':
        return lengths  # legacy yara format: no per-rule metadata to parse
    crt_set = set(_CRT_INIT_LIST + _CRT_FINI_LIST)
    for i, line in enumerate(lines):
        if not line.startswith('rule '):
            continue
        name = line.split(' ')[1].rstrip('{').strip()
        pattern = lines[i + 7].strip('\t').strip('$pattern = {').strip(' }')
        fmt = re.sub(r'(?<=\().*?(?=\))', 'XX', pattern).split(' ')
        y_pattern_length = len(fmt) - fmt.count('??')
        r_funcs = set(lines[i + 2].strip('\t').split('"')[1].split(' '))
        if r_funcs & crt_set:
            y_pattern_length = 10**9  # always keep CRT init/fini rules
        lengths[name] = y_pattern_length
    return lengths


def compile_yara_file(yara_rule_path):
    # Compile the entire .yara file once and return
    # (rules, {rule_identifier: y_pattern_length}). Callers replicate
    # the historical multi-pass behaviour by filtering matching rules
    # whose identifier has length >= L per merge iteration, avoiding
    # the per-L recompile that the loop in run_one used to do.
    #
    # Compiled rules are persisted under STELFTOOLS_PATH/.cache/yara/ as
    # <basename>.yarc + <basename>.lengths.json. A warm hit deserialises
    # ~8x faster than recompiling, which is the dominant per-cfg cost
    # in the bruteforce driver. Cache invalidates when the .yara file
    # is newer than the cached pair.
    name = os.path.basename(yara_rule_path)
    cache_yarc = os.path.join(CACHE_DIR, name + ".yarc")
    cache_lens = os.path.join(CACHE_DIR, name + ".lengths.json")
    try:
        yara_mtime = os.path.getmtime(yara_rule_path)
        if os.path.getmtime(cache_yarc) >= yara_mtime \
                and os.path.getmtime(cache_lens) >= yara_mtime:
            with open(cache_yarc, 'rb') as fp:
                rules = yara_x.Rules.deserialize_from(fp)
            with open(cache_lens) as fp:
                lengths = json.load(fp)
            return rules, lengths
    except (FileNotFoundError, OSError):
        pass

    with open(yara_rule_path) as fp:
        src = fp.read()
    rules = yara_x.compile(src)
    lengths = _parse_rule_lengths(yara_rule_path)

    # Write cache. tmp + atomic rename so a SIGINT mid-write does not
    # leave a half-baked .yarc that future runs would deserialise.
    # Parallel workers racing on the same file are safe because every
    # writer writes its own pid-suffixed .tmp before rename. Cache
    # writes are best-effort — a read-only cache dir or full disk just
    # forfeits the warm-up benefit.
    tmp_yarc = cache_yarc + '.tmp.' + str(os.getpid())
    tmp_lens = cache_lens + '.tmp.' + str(os.getpid())
    try:
        os.makedirs(CACHE_DIR, exist_ok=True)
        with open(tmp_yarc, 'wb') as fp:
            rules.serialize_into(fp)
        with open(tmp_lens, 'w') as fp:
            json.dump(lengths, fp)
        os.replace(tmp_yarc, cache_yarc)
        os.replace(tmp_lens, cache_lens)
    except OSError:
        for path in (tmp_yarc, tmp_lens):
            try:
                os.unlink(path)
            except OSError:
                pass

    return rules, lengths
