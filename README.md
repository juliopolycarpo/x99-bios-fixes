# x99-bios-fixes

Firmware defects found in two boards with an X99-derived AMI Aptio BIOS, with a patch for each one where a fix is justified. `x99fix` scans a ROM dump, reports which defects it contains, and builds a patched copy. Patches can be used alone or combined.

The two audited boards:

- **PR9:** B85 chipset.
- **MR9A:** Q87 chipset, vendor image `MNX99MR9APRO_230322`.

Both were tested with a Xeon E5-2680 v4. Many similar boards share this code; [docs/porting.md](docs/porting.md) shows how to check yours.

> **No patch here has been booted on real hardware.** Every change is checked offline: hashes, re-parsing and, in the original audit, execution of the patched code. None of that replaces a boot test. Only flash with an external programmer and a verified backup ([docs/flashing.md](docs/flashing.md)).

## Quick start

`x99fix` needs Python 3.10 or newer and nothing else:

```sh
git clone https://github.com/<owner>/x99-bios-fixes && cd x99-bios-fixes
./x99fix scan dump.bin
```

```
Board: mr9a
  B01-B06          DEFECT PRESENT  tier 1  Bound standard iMC transfers and propagate ordinary writer errors
  B02-B03          DEFECT PRESENT  tier 1  Separate DIMM counters and establish page zero during Auto discovery
  …
Patchable on this exact build: A02 A03 A07 B01-B06 B02-B03 B05 B08 B09 B10 B11 H01 H02 H05 R01
Build a patched copy? Enter ids, 'r' for recommended ['B01-B06', 'B02-B03'], or nothing to skip:
```

To build without the prompt:

```sh
./x99fix patch dump.bin --select recommended -o dump-fixed.bin
./x99fix patch dump.bin --select B02-B03 B01-B06 H05 -o dump-fixed.bin
```

The output is a new file next to a `.manifest.json` that lists every change. The input is never modified, and an existing output file is never overwritten. Nothing here touches the flash chip.

## What the patches fix

| Tier | Patch | Fixes |
|---|---|---|
| 1 | B02-B03 | DDR4 SPD detection probes the wrong DIMM slot and can read the wrong SPD page |
| 1 | B01-B06 | SPD bus waits have no timeout, and write errors are reported as success |
| 2 | B08, B05, B09, B10, B11, H05, R01, A02, A03, A07, S01, S02 | Error paths, S3/wake classification, SMM robustness, Super I/O writes, SMBIOS and ACPI |
| 2, manual | B01-B04-B06-B08, B07-B08 | Larger MRC fixes; the module grows and must be relocated by hand |
| hold | H01, H02 | Super I/O register changes whose hardware effect is unknown |

Each finding, its confidence and what the fix doesn't cover are in [docs/defects.md](docs/defects.md). POST codes and the known `b0`/`b7` hang are explained in [docs/post-codes.md](docs/post-codes.md).

### Combining patches

Patches combine freely unless they edit the same bytes. Each hunk checks its own original bytes, so the order doesn't matter, and applying patches one at a time gives the same image as applying them together. Three rules:

- A patch that contains another supersedes it (B01-B04-B06-B08 contains B01-B06 and B08). If the smaller one is already in the ROM, it's upgraded.
- Patches that overlap conflict (B04 vs B07; A02, A03 and A07 on the DSDT). `x99fix` refuses the combination.
- Fixes already present in a ROM are kept when you add more.

### How a ROM is rebuilt

1. Each module is located by its FFS GUID and matched against the recorded original. Known fixes are undone first to recover it.
2. All selected hunks are applied to the original.
3. LZMA sections are recompressed with the original properties, and FFS checksums are recomputed.
4. Same-size modules stay in place. If a compressed DXE file grows, the files after it move into the volume's free space.
5. The packer refuses to move anything that runs from a fixed flash address: PEI modules, execute-in-place images, FIXED files, the volume top file, and PAD files that carry data.
6. The output is parsed again, every selected patch must read `fixed`, and every byte outside the touched volumes must be unchanged.

## Repository layout

| Path | Contents |
|---|---|
| `patches/` | One JSON record per fix: per-board hunks, hashes and signature context |
| `src/x99fix/` | Scanner and packer (`uefi.py` firmware format, `hunks.py` patch engine, `rom.py` scan/build, `cli.py`) |
| `tests/` | Unit tests on synthetic firmware; an optional test runs every record against real dumps |
| `tools/setup-ghidra.sh` | Installs pinned Ghidra and ghidra-firmware-utils for analysis |
| `tools/ghidra-analyze.sh`, `tools/ghidra/` | Headless import and export of modules (C, assembly with bytes, JSON) |
| `docs/` | Defects, POST codes, manual patching, flashing, porting, references |

Vendor ROMs, extracted modules and datasheets are not included. Records hold only the changed bytes and 16 bytes of context around each change.

## Tests

```sh
PYTHONPATH=src:tests python3 -m unittest discover -s tests
# with stock dumps of the reference boards:
X99FIX_ROM_MR9A=mr9a.bin X99FIX_ROM_PR9=pr9.bin PYTHONPATH=src:tests python3 -m unittest test_rom.RealRomTests
```
