# MRC checkpoint breadcrumbs (offline diagnostic, revision 2)

> **Completed-pass logging has initial hardware evidence; failed-boot retention is not validated.** Revision 2 was flashed with exact full-chip readback verification. The first boot read `BF/00 location 0000`, ended, with zero failed passes. A later all-DIMMs-removed test reached POST `53`; after restoring RAM without clearing CMOS or removing the battery, no failed record was retained. The cause is unresolved. See [hardware observations](hardware-tests.md#mr9a-breadcrumb-diagnostic-revision-2--2026-11-08). This remains a separate diagnostic tool, outside the `x99fix` correction catalog.

When the MRC stops on `b0` or `b7`, nothing records where. The display shows only the major code, `B7` covers about 36 training steps, and the next boot overwrites the display. This patch keeps the full MRC checkpoint (major, minor, 16-bit location) in upper-bank CMOS. If a pass dies before it ends, the patch freezes that checkpoint so Linux can read it after the next good boot.

It targets the MR9A `UncoreInitPeim` with B01-B06 and B02-B03 applied. It won't apply to PR9 or to a stock module.

## How it hooks in

The MRC checkpoint setter `FFE0FE3C` packs `major<<24 | minor<<16 | location` into context offset `+22124`. For the boot socket it then calls the port-80 writer `FFE4276C`, from one site only (`FFE0FEA9`). The patch points that call at a new hook. The hook sends the major code to port 80 as before, then records it.

The PEI volume has no free space, so all the code fits inside the module:

| Region | Address | Used | What was there |
|---|---|---|---|
| r0 | `FFE4276C` | 29 of 30 | the old port-80 writer, now unused |
| ra | `FFE613A2` | 88 of 88 | NOP run freed by B01-B06 |
| rb | `FFE61903` | 52 of 53 | NOP run freed by B01-B06 |
| call site | `FFE0FEA9` | 5 | `call FFE4276C` becomes `call FFE613A2` |

The recovered direct branches and an absolute-pointer scan contain no target inside the NOP runs, and no relocation entry covers a patched byte. This static coverage does not exclude arbitrary computed jumps. Because the runs only exist once B01-B06 is applied, the patch depends on B01-B06. It also replaces the old port-80 writer, so it can't be combined with a diagnostic that changes that writer to show minor codes.

The source is [tools/mrc-breadcrumbs.asm](../tools/mrc-breadcrumbs.asm). At the call site `esi` is the context and `edi` the packed value. The caller loads `edi=6` at `FFE0FEAF` and zeroes `ebx` at `FFE0FEE0` before using them again. An earlier exit restores both from the outer function's stack. The hook retains `esi`, `ebp` and the caller's stack. Tests execute the real setter, both exits, the polling path and the non-boot-socket path, comparing original and patched register preservation, context writes, CSR-helper arguments and port-80 output.

Revision 1 stopped its copy loop when the shifted checkpoint became zero. An unexpected zero major could leave old high bytes in the slot: `00123456` following `B7310302` was read back as `B7123456`. Revision 2 writes exactly four bytes using `bh` as the counter. `bswap eax` obtains the major for the initial port write, and `inc edx` advances the slot index without a low-byte carry in `E1`–`E8`; these save enough space to keep all four regions the same size. No original MRC control flow is changed.

## CMOS layout

| Index | Meaning |
|---|---|
| `E0` | state: `A0`, plus `2` for slot 1, plus `1` once the pass has ended. Any other value means not armed |
| `E1`–`E4` | slot 0: packed checkpoint, little-endian |
| `E5`–`E8` | slot 1 |
| `E9` | failed-pass count, stops at `FF`, zeroed when arming |

A pass starts at checkpoint `B0/00` and ends at `BF` (MRC done) or `AF` (MRC reset request, such as the frequency-change reset after a DIMM swap). If a new pass starts while the previous one never ended, the patch switches slots, which freezes the dead pass's record, and increments the count. Nothing is recorded after a pass ends.

Before flashing the diagnostic, `E0`–`E9` read `FF` on the reviewed MR9A. AMI's CmosPei uses the same ports (72h/73h) and the same `80`–`FF` logical indexing. This snapshot alone does not establish exclusive ownership.

The previously open CmosManager questions are resolved for this firmware:

- `CmosPei` initialization at `FFE87F58`/`FFE87F64` sets the managed/default/checksum bounds to `40h`–`46h`. Its 12-entry token table at `FFE87CA0` names only those indexes. The checksum loop at `FFE88ECE` uses those bounds; DXE receives the map in the CMOS HOB. The diagnostic range is outside this map.
- `PlatformEarlyInit` sets RTC upper-bank enable (RCBA `3400h`, bit 2) at `FFDBC91F`, writing `FED1F400h`. Its entry calls the setup routine at `FFDBBACD`, which calls this enable routine at `FFDBCA8A`. Later, at `FFDBBB94`, it installs a PPI list containing `9A7EF41E-C140-4BD1-B884-1E11240B4CE6`, required by UncoreInitPeim's AND dependency expression. Upper-bank access therefore precedes MRC dispatch on this build. Intel 8-series PCH datasheet §10.1.47 defines the enable bit; §12.6 describes the two CMOS banks.

These observations apply to the exact reviewed firmware. They do not reserve the bytes against every possible option ROM, later firmware version or other writer.

## Building an offline ROM

The builder requires NASM and the exact B01-B06 + B02-B03 UncoreInitPeim. It also accepts the tested stage-2 bundle, which retains that component. Start with a saved dump of your own board:

```sh
python3 tools/build_breadcrumbs.py stage2-readback.bin -o mr9a-breadcrumbs-v2.bin
```

The builder authenticates the component SHA-256 and the surrounding CmosPei, CmosDxe and PlatformEarlyInit profiles (including their reviewed B05/B09 variants). It checks all original regions and relocation coverage, retains the reviewed XIP address, and rebuilds its FFS checksum. It reparses the output and requires unchanged ROM size, FV headers, file positions and every unselected file. It refuses an existing output or manifest. No firmware device is opened.

Keep the input dump and generated manifest. The diagnostic changes UncoreInitPeim's identity, so the normal scanner can no longer authenticate that module against correction-only records. Apply further corrections to the saved input and rebuild the diagnostic afterward; do not stack `x99fix` blindly on a diagnostic ROM. B04/B07 and other code-cave users need separate recomposition and validation.

## Reading it

```sh
sudo python3 tools/read_breadcrumbs.py
```

The reader uses ports 72h/73h only and writes nothing to CMOS. A CMOS clear erases the record, so after a stuck boot, recover with the DIMM or GPU change first and read the record before clearing CMOS.

The logger ends the tracked pass at `BF`; later POST/console errors such as
no-GPU `d6` are outside its scope. A completed `BF` record and zero failed MRC
passes after a `d6` attempt are consistent with this boundary. That observation
does not resolve the missing failed record in the separate no-RAM `53` test.

## Before flashing

- Follow the [backup, programmer recovery and readback procedure](flashing.md). On the first test, confirm normal/cold boot, unchanged setup settings, and a readable completed MRC pass. Then check retention across another boot before using the logger to investigate a hang.
- **A stored pass is not a boot-success verdict.** `BF` ends MRC, not the entire boot; `AF` marks an intentional reset request. The count increments when the next `B0/00` sees an unfinished pass. Power loss and an interrupted normal boot can also increment it.
- **The record is best effort.** CMOS data and state writes are not a reset-atomic transaction, carry no checksum, and are not synchronized against an unrelated CMOS writer. A reset during a write may leave a mixed record.
- **Location is checkpoint-specific.** For example, `B0/02` at `FFE4202A`–`FFE4205D` packs socket/channel/DIMM nibbles. Other call sites need their own interpretation; the reader prints the raw 16-bit field.
- **Granularity.** A hang inside a step without its own checkpoint, such as an unbounded SPD or PCU-mailbox wait, shows the last checkpoint before it.

## Tests

```sh
PYTHONPATH=src:tests python3 -m unittest test_breadcrumbs
# Also execute the real surrounding firmware and test packing:
X99FIX_ROM_MR9A=stock-mr9a.bin PYTHONPATH=src:tests python3 -m unittest test_breadcrumbs_rom
```

The hook tests assemble the source with NASM and run it under Unicorn against a fake CMOS bus. Without both tools they're skipped, and only the reader tests run. They cover arming after a CMOS clear, a good boot, stuck `b7`, stuck `b0`, an MRC reset pass, a failure followed by a reset pass, two failures, count saturation, zero-major and repeated-byte records, register preservation, and writes confined to `E0`–`E9`. Supplying the stock MR9A dump additionally runs 48 original/patched executions through the real setter and checks source authentication, already-patched rejection and ROM packing. None of these tests establishes physical CMOS retention or timing.
