# B04/B07 worker failure boundary

The B01-B04-B06-B08 and B07-B08 records include a conservative IA32 guard on both boards. Before entering the existing failure bus/worker gate, it requires the active bitmap to contain exactly the bootstrap socket and the context's prior remote-worker-initialization byte to be zero. Other contexts take the existing terminal halt before ME callbacks, reset/retry handling or a return to PEI.

This corrects the old assumption that shutdown mailbox `0x08024094` changing from `0x99` to zero uniquely acknowledges worker termination. The original normal receive tail can also overwrite a concurrent shutdown request with zero and return to the manager. A later idle bus snapshot cannot exclude its next write.

The guard runs only on the existing failure/reset-continuation paths. It preserves the original gate's frame and registers and leaves normal successful training unchanged. For a valid sole BSP without initialized workers, the existing bus safety, callback, cleanup and error-return checks still execute. If worker quiescence is uncertain, failure intentionally halts even when training-error halt was disabled.

## Reproduction

`tools/memory-failure-guard.asm` is the complete added guard. `tools/rebuild_memory_guards.py` requires Python and NASM; the CLI itself still requires only Python. Supply the exact unpatched reference dumps:

```sh
python3 tools/rebuild_memory_guards.py --pr9 stock-pr9.bin --mr9a stock-mr9a.bin
```

The script authenticates both source components and the legacy candidates, reconstructs the guard, updates the PE aggregate/final-section sizes, and regenerates the JSON result hashes and hunks. The records retain their original source hashes, original signatures and finding provenance. `memory_failure_guard` stores a reversible recipe that permits an identical rebuild from the current records. Only the two JSON files are written; ROMs are read as ordinary files and no firmware devices are opened.

The patch replaces six bytes of the old gate's prologue with a relative jump to an appended trampoline. The trampoline reproduces that prologue, checks worker state and either resumes at the next original instruction or calls the original terminal halt. All added transfers are relative. Existing code offsets, relocation entries and data directories remain fixed. Each candidate grows by 96 bytes beyond its legacy size; total growth from stock is 3,168 bytes for B04 and 2,240 bytes for B07.

The previous unguarded result hashes are retained in the recipe only for authenticated reconstruction. They are not accepted as current fixed results. An old manually packed image must be reconstructed and validated with the updated component; do not silently treat it as the new revision. Images assembled using other compositions also need their own composition and layout validation.

## Tests and limits

```sh
PYTHONPATH=src:tests python3 -m unittest discover -s tests
X99FIX_ROM_PR9=stock-pr9.bin X99FIX_ROM_MR9A=stock-mr9a.bin \
  PYTHONPATH=src:tests python3 -m unittest discover -s tests
```

The optional native checks require `unicorn` and `pefile`; guard-source checks also require NASM. They execute valid BSP indices, multiple/empty/foreign active bitmaps, out-of-range BSP indices, and nonzero worker history. With dumps supplied, all four exact exported components are checked at their original bases and a relocated base, with exact application/reversal, PE geometry and idempotent assembly checks.

These remain manually packed PEI candidates. The automatic packer still refuses the required XIP relocation. Offline tests do not establish physical boot, wake, electrical timing, or repair of POST 60/67.
