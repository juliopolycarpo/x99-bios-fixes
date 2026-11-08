# Checking another X99 board

Many low-cost X99-family boards ship AMI Aptio images that look closely related to these two. Where they share a module, the same defect may sit at a different offset. This guide covers finding out whether yours does, and building a tested record for your board.

## 1. Get a clean dump

Read the chip with an external programmer, as in [flashing.md](flashing.md). A vendor update file also works for scanning, but patch the dump you will actually write back.

## 2. Scan it

```sh
./x99fix scan dump.bin
```

- **Known build:** if the board's modules match PR9 or MR9A exactly, every record reports `present` or `fixed` and can be patched directly.
- **Different build:** otherwise, the scan matches each hunk's 16-byte context, with relocated addresses and branch displacements masked out:
  - `likely-present`: every hunk of the defect matched exactly once. The defect is probably there.
  - `not-detected`: the code differs, or the module doesn't exist. This doesn't prove the defect is absent.

`x99fix` never patches a module whose hash differs from a recorded original. You need a record for your board first.

## 3. Set up the analysis tools

| Tool | Used for | Install |
|---|---|---|
| Python 3.10+ | `x99fix` (standard library only) | distribution package |
| Ghidra 12.2 + ghidra-firmware-utils | disassembly and decompilation of PEI/DXE/SMM modules | `tools/setup-ghidra.sh` |
| JDK 21+, gcc | building the Ghidra extension | `apt install openjdk-21-jdk build-essential` |
| UEFITool 0.28 / UEFIExtract | browsing images, cross-checking `x99fix` | [LongSoft/UEFITool](https://github.com/LongSoft/UEFITool) releases |
| ACPICA `iasl` | disassembling and rebuilding DSDTs | `apt install acpica-tools` |
| flashrom + SPI programmer | reading and writing the chip | `apt install flashrom` |

`tools/setup-ghidra.sh` downloads a pinned Ghidra and Gradle and checks their SHA-256. It then builds the firmware extension from a pinned commit, with a two-line patch for Ghidra 12.2. Everything installs under your home directory:

```sh
tools/setup-ghidra.sh                     # installs to ~/.local/share/x99-bios-fixes
tools/setup-ghidra.sh --prefix /opt/re    # or choose a prefix
```

## 4. Extract and analyze the module

The GUIDs are the same across these builds. Find a record's GUID in `patches/<ID>.json` (`ffs_guid`).

```sh
./x99fix extract dump.bin --guid D71C8BA4-4AF2-4D0D-B1BA-F2409F0C20D3 -o UncoreInitPeim.pe
tools/ghidra-analyze.sh work/project work/exports UncoreInitPeim.pe
```

The export writes three files:

- `UncoreInitPeim.c`: approximate decompilation.
- `UncoreInitPeim.asm`: every instruction with its exact bytes.
- `UncoreInitPeim.json`: functions, calls and address ranges.

Do the same for the reference board's module, from its own dump, to compare the two.

## 5. Draft the hunks for your build

```sh
./x99fix derive --patch B02-B03 --reference mr9a --component UncoreInitPeim \
  --module UncoreInitPeim.pe > draft.json
```

`derive` works only when every hunk's signature matches exactly once. It writes a board entry with your offsets and hashes, marked `UNREVIEWED`. It doesn't fix the patch bytes. Any absolute address, call displacement or stack offset inside `after` comes from the reference build and may be wrong for yours.

For each hunk:

1. Find the hunk's address in your `.asm` and in the reference board's `.asm`.
2. Check that the surrounding function does the same thing in both.
3. Recompute any address or displacement in `after` for your build.
4. Check that the patched instructions decode as intended. You can disassemble the patched module again.

## 6. Add the board

1. Add your board under `boards` in the record, with a short name (for example `"x99-tf"`). Use the reviewed component entry and delete the `draft` field.
2. Run the test suite, with your dump if you have one:

```sh
PYTHONPATH=src:tests python3 -m unittest discover -s tests
X99FIX_ROM_MR9A=mr9a.bin X99FIX_ROM_PR9=pr9.bin PYTHONPATH=src:tests python3 -m unittest test_rom.RealRomTests
```

3. `./x99fix scan dump.bin` should now detect your board and report the defect as `present`. A build from `./x99fix patch` should report it as `fixed`.

## Record format

```json
{
  "schema": 1,
  "id": "B02-B03",
  "title": "…",
  "findings": ["B02", "B03"],
  "finding_confidence": {"B02": "C0"},
  "local_fix_confidence": "C1",
  "physical_fix_confidence": "C2",
  "hardware_tested": false,
  "tier": 1,
  "packing": "automatic",
  "supersedes": [],
  "conflicts": [],
  "limits": "what the fix does not cover",
  "boards": {
    "mr9a": {"applicable": true, "components": ["…"]},
    "pr9": {"applicable": false, "reason": "…"}
  }
}
```

- `tier` is `1` (apply first), `2`, or `"hold"`. Hold records are refused without `--allow-hold`.
- `packing` is `"manual"` when the packer is known not to fit the change on the reference boards; the field is optional and defaults to automatic.
- `supersedes` lists records this one fully contains. Selecting both keeps this one; a ROM that already has the smaller fix is upgraded.
- `conflicts` lists records that edit the same bytes. They can never be combined.
- Components are described in [manual-patching.md](manual-patching.md). Each hunk can also carry `wild_before` and `wild_after`: the positions in the signature window (context + bytes + context) that match any byte on other builds.
