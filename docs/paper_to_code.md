# Paper to code

A map from the two reference papers behind stelftools to the modules
that implement them. The intent is that a researcher who has just read
either paper can descend into the code without re-tracing the design.

## Primary reference (2021)

> Akabane, S. & Okamoto, T. (2021). *Identification of toolchains used
> to build IoT malware with statically linked libraries*. Procedia
> Computer Science 192, 5130-5138.
> <https://www.sciencedirect.com/science/article/pii/S1877050921020305>

This is the load-bearing paper for the current implementation: it
defines the multi-architecture pattern-matching pipeline, the
per-architecture address-discovery taxonomy, and the strict
"all library functions identified" gate.

### §3.1 -- Library function pattern generation

| Paper concept | Implementation |
|---|---|
| Walk every static-library function | `stelftools/generate/__init__.py::mkrule_and_other` |
| Per-object opcode extraction pipeline | `stelftools/generate/opcodes.py::extract_opcodes` |
| Per-archive driver (ar-walking) | `stelftools/generate/opcodes.py::extract_opcodes_from_arfile` |
| Relocation -> wildcard | `stelftools/generate/arch/<isa>.py::apply_relocation` (17 architectures) |
| crti.o / crtn.o pair merge (single rule across linker glue) | `stelftools/generate/crt.py::collect_funcs`, `merge_pairs` |
| Dependency list (`.dlist`, caller / callee pairs) and alias list (`.alist`, symbol-name aliases sharing one opcode body) | `stelftools/generate/deparse.py` |
| Linker optimisation (peephole, R_386_TLS_GOTIE etc.) replaced with regex wildcards | `stelftools/generate/arch/<isa>.py::apply_relocation` per-arch logic |
| 200-byte rule body length cap (Fig 3.1 in both papers) | `stelftools/generate/opcodes.py::MAXIMUM_PATTERN_LENGTH` (raised to 15000 to accommodate RISC-V linker relaxation; docstring notes the divergence) |

### §3.2.1 -- Address discovery (locations A / B / C)

| Paper location | Architectures | Implementation |
|---|---|---|
| A (call-instruction operand) | ARC, ARM, m68k, PowerPC, SPARC, Intel 80386, x86_64 | `stelftools/elf/disasm.py::parse_inst` per-arch branches |
| B (Global Offset Table) | MIPS 32-bit, MIPS 64-bit | `stelftools/elf/mips_got.py` + the EM_MIPS post-pass in `disasm.py:parse_inst` |
| C (literal pool / function address table) | Renesas sh4 | EM_SH branch in `stelftools/elf/disasm.py:parse_inst` (dereferences the `mov.l @(disp,pc),Rn` slot) |

### §3.2.2 -- Small-function exclusion (per-arch X-byte threshold)

The 2021 paper picks a per-architecture X (Table 5: m68k/sh4/SPARC=4,
PowerPC=5, ARC/ARM/MIPS/x86_64=6, Intel 80386=7) and does two-pass
matching: large functions first, then the small-function residuals.

stelftools uses a different multi-pass merge: `arch_pattern_length`
returns a starting bucket and the orchestrator iterates `L = N..1`,
merging matches at each L. The shape produces equivalent matches in
practice but the algorithm is not a direct translation of the paper's
two-pass scheme; the current bucket values (in
`stelftools/match/orchestrator.py::arch_pattern_length`) were chosen
empirically and do not match Table 5 row-for-row.

### §3.3 -- Toolchain identification

The 2021 paper's claim:

> If all library functions in a sample can be identified by pattern
> matching, the toolchain used to generate the pattern is assumed to
> be that used to build the sample.

| Paper concept | Implementation |
|---|---|
| "All library functions identified" gate | `stelftools identify --strict` (= `--threshold 1.0`) |
| Per-toolchain candidate scoring | `stelftools/drivers/identify.py::select_best` |
| Top-cfg verdict construction | `stelftools/drivers/identify.py::_compute_verdict` |
| Verdict + ranking rendering | `stelftools/drivers/identify.py::_print_verdict`, `identify_without_cfg` |
| Oldest-toolchain tie-break (paper claim) | NOT implemented (`select_best` returns the score-descending ranking; equal scores fall back to filesystem walk order). Adding this is tracked as follow-up. |

### §4.1 / Table 6 -- Build tools studied

| Paper build tool | Family directory under `signatures/` |
|---|---|
| Firmware Linux 0.9.6 ~ 0.9.11 | `firmware-linux/` (prefix `fl-`) |
| Aboriginal Linux 1.0.0 ~ 1.4.5 | `aboriginal-linux/` (prefix `al-`) |
| Buildroot 2018.02 ~ 2019.05 | `buildroot/` (prefix `br-`) |
| Yocto BitBake 1.40 | not currently shipped |
| Crosstool-NG 1.23.0 ~ 1.24.0 | `crosstool-ng/` (prefix `ct-ng`) |
| Buildroot (Synopsys prebuilt) | `synopsys-arc-gnu/` (prefix `synopsys_arc_gnu`) |
| Buildroot (Bootlin prebuilt) | `bootlin-stable/` (prefix `bl-stable-`) |

`stelftools/families.py` records the prefix -> family routing.
`stelftools/signatures_manifest.json` lists the per-(family, arch)
tarballs published as GitHub Release attachments that `stelftools
fetch` pulls.

## Predecessor reference (2020)

> Akabane, S. & Okamoto, T. (2020). *Identification of library
> functions statically linked to Linux malware without symbols*.
> Procedia Computer Science 176, 3436-3445.
> <https://www.sciencedirect.com/science/article/pii/S1877050920319487>

This earlier paper covers Intel 80386 only and is the source of two
ideas that still live in the codebase:

* **Libc-region anchors** (§4.2) -- the GNU linker emits C runtime
  prologue objects (crt1, crti, crtbeginT) before the libc archive
  and the C runtime epilogue (crtend, crtn) after it; the first / last
  libc anchors carve the libc region out of that fixed ordering.
  Implemented in `stelftools/match/coverage.py::{first_libc_anchor,
  last_libc_anchor, libc_funcs_in_crt_area}`.
* **Permissive 90% threshold** (§5.2.2) -- "A coverage of at least 90%
  of the library functions means that the toolchain has been
  identified". The 0.9 default in
  `stelftools/match/coverage.py::TOOLCHAIN_IDENTIFIED_THRESHOLD` mirrors
  this claim; on the noisy real-world samples the tool is typically
  pointed at, the 2020 bar is more useful than the 2021 paper's strict
  100% bar.

## Heuristics added beyond the papers

Neither paper covers stelftools' three heuristics that disambiguate
multi-aliased rule hits:

| Heuristic | Implementation |
|---|---|
| Link-order disambiguation | `stelftools/match/heuristics/linkorder.py` (driven by `dub_maker.py`) |
| Dependency-based disambiguation | `stelftools/match/heuristics/depend.py` |
| Consecutive-candidate filter (post-pass) | `stelftools/match/heuristics/consecutive.py` |

Together they bring the reported accuracy on the README's 150-sample
benchmark to 97.18%; the two papers' baseline matched without these
post-passes.

## Operational glue (not in either paper)

| Concern | Implementation |
|---|---|
| CLI dispatch (`stelftools <verb>`) | `stelftools/drivers/cli.py` |
| Single-config (`--cfg PATH`) + multi-config identification | `stelftools/drivers/identify.py` |
| ELF symtab write-back for downstream tools | `stelftools/drivers/symbolize.py` + `stelftools/elf/symtab_write.py` |
| Signature distribution via GitHub Releases | `stelftools/drivers/fetch.py` + `tools/ci/publish_signatures_release.py` |
| YARA rule cache | `stelftools/match/yara.py::compile_yara_file` (yara-x binary serialise -> `.cache/yara/*.yarc`) |
