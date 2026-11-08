# MRC checkpoint breadcrumbs (sketch)

> **Sketch only.** The bytes below are assembled and executed offline. They aren't an `x99fix` record yet, and they haven't been packed into a ROM or booted. An open CMOS question (below) has to be answered before anyone flashes them.

When the MRC stops on `b0` or `b7`, nothing records where. The display shows only the major code, `B7` covers about 36 training steps, and the next boot overwrites the display. This patch keeps the full MRC checkpoint (major, minor, 16-bit location) in upper-bank CMOS. If a pass dies before it ends, the patch freezes that checkpoint so Linux can read it after the next good boot.

It targets the MR9A `UncoreInitPeim` with B01-B06 and B02-B03 applied. It won't apply to PR9 or to a stock module.

## How it hooks in

The MRC checkpoint setter `FFE0FE3C` packs `major<<24 | minor<<16 | location` into context offset `+22124`. For the boot socket it then calls the port-80 writer `FFE4276C`, from one site only (`FFE0FEA9`). The patch points that call at a new hook. The hook sends the major code to port 80 as before, then records it.

The PEI volume has no free space, so all the code fits inside the module:

| Region | Address | Used | What was there |
|---|---|---|---|
| r0 | `FFE4276C` | 27 of 30 | the old port-80 writer, now unused |
| ra | `FFE613A2` | 88 of 88 | NOP run freed by B01-B06 |
| rb | `FFE61903` | 52 of 53 | NOP run freed by B01-B06 |
| call site | `FFE0FEA9` | 5 | `call FFE4276C` becomes `call FFE613A2` |

No branch lands inside the NOP runs, and no relocation entry covers a patched byte. Because the runs only exist once B01-B06 is applied, the patch depends on B01-B06. It also replaces the old port-80 writer, so it can't be combined with a diagnostic that changes that writer to show minor codes.

The source is [tools/mrc-breadcrumbs.asm](../tools/mrc-breadcrumbs.asm). The register contract is in its header: at the call site `esi` is the context and `edi` the packed value, and the caller reloads `edi` and zeroes `ebx` before reading them again.

## CMOS layout

| Index | Meaning |
|---|---|
| `E0` | state: `A0`, plus `2` for slot 1, plus `1` once the pass has ended. Any other value means not armed |
| `E1`–`E4` | slot 0: packed checkpoint, little-endian |
| `E5`–`E8` | slot 1 |
| `E9` | failed-pass count, stops at `FF`, zeroed when arming |

A pass starts at checkpoint `B0/00` and ends at `BF` (MRC done) or `AF` (MRC reset request, such as the frequency-change reset after a DIMM swap). If a new pass starts while the previous one never ended, the patch switches slots, which freezes the dead pass's record, and increments the count. Nothing is recorded after a pass ends.

On the tested MR9A, `E0`–`E9` read `FF`. AMI's CmosPei uses the same ports (72h/73h) and the same `80`–`FF` indexing.

## Reading it

```sh
sudo python3 tools/read_breadcrumbs.py
```

The reader uses ports 72h/73h only and writes nothing to CMOS. A CMOS clear erases the record, so after a stuck boot, recover with the DIMM or GPU change first and read the record before clearing CMOS.

## Before flashing

- **CmosManager's map isn't decoded.** If `E0`–`E9` fall inside AMI CmosManager's checksummed area, every write would make the board load setup defaults. One check that needs no flash: write test values to `E0`–`E9` from Linux, reboot, and confirm they persist and setup didn't reset.
- **The upper bank must already be enabled when the MRC runs.** CmosPei uses it in PEI, but the module order and the PCH upper-128 enable at that point haven't been checked.
- **The location field isn't decoded.** It probably holds socket, channel, DIMM or rank.
- **Granularity.** A hang inside a step without its own checkpoint, such as an unbounded SPD or PCU-mailbox wait, shows the last checkpoint before it.

## Tests

```sh
PYTHONPATH=src:tests python3 -m unittest tests.test_breadcrumbs
```

The hook tests assemble the source with NASM and run it under Unicorn against a fake CMOS bus. Without both tools they're skipped, and only the reader tests run. They cover arming after a CMOS clear, a good boot, stuck `b7`, stuck `b0`, an MRC reset pass, a failure followed by a reset pass, two failures, count saturation, register preservation, and writes confined to `E0`–`E9`.
