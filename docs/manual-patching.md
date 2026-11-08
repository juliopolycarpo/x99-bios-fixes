# Patching by hand

Use this when you want to see every byte change, when a patch is marked *manual*, or when you'd rather not run the packer. Either way, read [flashing.md](flashing.md) first.

## What a patch record says

Each file in `patches/` describes one fix. For every board it applies to, it lists the components to change. This excerpt is from the PR9 entry of `B02-B03.json`:

```json
{
  "name": "UncoreInitPeim",
  "ffs_guid": "D71C8BA4-4AF2-4D0D-B1BA-F2409F0C20D3",
  "leaf": "pe32",
  "source_sha256": "a645b2ea…",
  "result_sha256": "…",
  "hunks": [
    {"offset": 470036, "before": "20", "after": "24",
     "context_before": "…", "context_after": "…"}
  ]
}
```

- `ffs_guid` is the GUID of the FFS file that holds the module.
- `leaf` is the section inside it: `pe32` (the PE image) or `acpi-table` (a DSDT inside a RAW section).
- `offset` is a decimal byte offset into the **extracted module**, not into the ROM.
- `before` and `after` are hex. At `offset`, the original bytes must equal `before`; replace them with `after`.
- `context_before` and `context_after` are the 16 bytes around the hunk. Use them to find the spot in a hex editor.
- An empty `before` means "append `after` at the end of the module".
- `source_sha256` must match your extracted module before you start, and `result_sha256` must match when you finish.

## Method 1: x99fix extract and replace

```sh
# 1. Extract the module
./x99fix extract dump.bin --guid D71C8BA4-4AF2-4D0D-B1BA-F2409F0C20D3 -o UncoreInitPeim.pe
sha256sum UncoreInitPeim.pe          # must equal source_sha256

# 2. Edit every hunk with a hex editor (offsets are decimal; 470036 = 0x72C14)

# 3. Check the result
sha256sum UncoreInitPeim.pe          # must equal result_sha256

# 4. Put it back into a new image
./x99fix replace dump.bin --guid D71C8BA4-4AF2-4D0D-B1BA-F2409F0C20D3 \
  --input UncoreInitPeim.pe -o patched.bin
./x99fix scan patched.bin            # the record should now read "fixed"
```

`replace` recompresses LZMA sections with the original parameters and recomputes FFS checksums. If the module changed size, it refuses unless you pass `--allow-resize`. Even then, it won't move an execute-in-place PEI module.

## Method 2: UEFITool

1. Open the dump in UEFITool 0.28 (the old engine). The newer NE builds can view and extract but not replace.
2. Search for the GUID and open the file. Select its `PE32 image section` and choose *Extract body*.
3. Edit and check the hashes as in method 1.
4. Choose *Replace body* on the same section and save the image.
5. Open the saved image again and check the module's body hash.

For PEI modules, which are uncompressed and run in place, a same-size edit changes only the hunk bytes. UEFITool should leave the file in place and update its checksums; confirm this with `./x99fix list` afterwards. Compressed DXE modules are recompressed, and the stream size can change. Check the layout afterwards the same way.

## Manual-only patches: B01-B04-B06-B08 and B07-B08

These grow UncoreInitPeim, by 3,168 and 2,240 bytes, including the [worker-safety guard](memory-guard.md). UncoreInitPeim runs in place from flash, and the PEI volume on both boards has no free space. Fitting the bigger module means three steps:

1. Moving PEI modules into free space elsewhere in the volume. The PR9 PEI volume has a large erased PAD file; check your own layout with `./x99fix list`.
2. Rebasing each moved module: applying its PE relocations and updating ImageBase to the new flash address.
3. Leaving the fixed areas alone: microcode, FIT, AP startup and the volume top file.

This was done once, offline, for a PR9 test image. It isn't automated here because the layout is board-specific, and a mistake bricks the board. If you attempt it:

- Verify each moved module rebased against its original.
- Keep every fixed-address structure byte-identical.

## Checking your work

- `./x99fix scan patched.bin` reports each record as `fixed`, `present` or `partial`.
- `./x99fix list patched.bin` shows the volumes and files, so you can compare the layout with the original.
- Compare the two images with `cmp -l dump.bin patched.bin | wc -l`. For same-size PEI patches, the count should equal the number of hunk bytes.
