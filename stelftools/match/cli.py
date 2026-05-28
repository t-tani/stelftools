"""Legacy ``stelftools-ident`` console-script entry point.

Argument parsing and the ``main`` flow stay isolated from the library
surface so programmatic consumers (the ``stelftools identify`` driver,
the IDA / Ghidra / radare2 / qiling plugins) never see argparse
symbols leak into their namespace. New code should call the verb
``stelftools identify`` instead; this module survives only to back the
``stelftools-ident`` legacy shim under
:mod:`stelftools.drivers.legacy_shims`.
"""

import argparse
import json
import os

from . import output, run_one


def get_target_list(targets, lm_flag):
    if lm_flag == True:
        with open(targets[0]) as f:
            target_list = f.readlines()
            target_list = [l.replace('\n', '') for l in target_list]
            return target_list
    else:
        return targets


def set_args():
    parser = argparse.ArgumentParser()
    # new
    parser.add_argument('-cfg', help = 'target path')
    parser.add_argument('-target', help = 'target path')
    # old
    parser.add_argument('--yara', help = 'yara rule path')
    parser.add_argument('--arch', help = 'target architecture')
    #parser.add_argument('--pattern_length', '-pl', default = 8, type = int)
    parser.add_argument('--output_style', '-o', default='default', help = 'output style')
    parser.add_argument('--virtual_addr', '-va', action='store_true', help = 'output virtual address')
    parser.add_argument('--list_mode', '-lm', action='store_true', help = 'list mode')
    parser.add_argument('--alias_list', '-al', help = 'Enable function name identification by function dependency')
    parser.add_argument('--id_linkorder', '-id_l', help = 'Path to toolchain used to identify function names by function link order')
    parser.add_argument('--id_depend', '-id_d', help = 'Enable function name identification by function dependency')
    args = parser.parse_args()
    return args


def main():
    args = set_args()

    if args.cfg and os.path.exists(args.cfg):
        with open(args.cfg) as cfg_fp:
            cfg_info = json.load(cfg_fp)
        target_info = run_one(args.target, cfg_info, cfg_path=args.cfg)
    elif args.yara is not None:
        cfg_info = {
            'arch': args.arch,
            'yara_path': args.yara,
            'compiler_path': args.id_linkorder or '',
            'alias_list_path': args.alias_list or '',
            'dependency_list_path': args.id_depend or '',
        }
        target_info = run_one(args.target, cfg_info)
    else:
        print("[ERROR] wrong argument")
        exit(-1)

    output(target_info, args.target, args.output_style)
