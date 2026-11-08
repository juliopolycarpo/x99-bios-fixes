# Initial hardware observations

## MR9A stage 1 — 2026-11-08

- Board: MACHINIST E5-MR9A PRO V1.2, Intel Q87, 64 GB installed as four 16 GB DIMMs.
- Selected records: **B01-B06 + B02-B03** together. No other corrections were included.
- The image was built from two matching fresh full-chip reads of that board, then flashed with write verification and a separate exact full-chip readback.
- The user reports that both normal and cold boots behave normally and boot time is unchanged. Their follow-up qualification is that the patches have not interrupted normal motherboard operation **at least so far**.
- Three distinct post-flash Linux boots were captured at the first review. Installed DIMM capacity, physical-memory total and PCI inventory matched the baseline; captured EDAC error counters were zero, and the reviewed kernel logs contained no matching machine-check or I/O errors.
- Kernel MemTotal varied by 16–24 KiB, exactly accounted for by early reserved-memory differences; no DIMM/channel capacity loss was observed.

The applied component SHA-256 was `95a0d4deb0d285ee4ee9ff9f59f9533f9ea14117af27fa0972343e5806a936bd`.
The board-specific flashed image SHA-256 was `a5bdac305b59216d49ac8aac65a56056242e5fcecdaecf142d8a57d2bdb8f985`.

This is **initial boot-compatibility evidence on one board**. Exact timing and warm/cold cycle counts were not supplied. Before the next firmware experiment, Linux memtester 4.7.1 passed four parallel locked 1 GiB allocations, each with all default patterns for one loop (4 GiB total, about seven minutes). All four processes exited zero; captured EDAC counters remained zero and no matching kernel machine-check/I/O errors appeared during the run. A preceding 32 GiB run was intentionally stopped before completion at the user's request for the smaller screen and is not counted as a completed pass. A four-pass offline Memtest86+ result has not been reported. None of these observations proves repair of the original intermittent boot failure or validates other board revisions, DIMM configurations or patch combinations.

Finding confidence, offline code-validation confidence and physical repair confidence remain separate. The records' broad `hardware_tested`/physical-confidence flags have not been promoted on the basis of these limited observations.

## MR9A stage 2 — 2026-11-08

The cumulative selection was **B01-B06 + B02-B03 + B05 + B10 + B11 + R01**, on the same MR9A PRO V1.2 / Q87 with four 16 GB DDR4 DIMMs. The fresh stage-1 backup was patched and validated; flashrom verification and a separate full-chip readback matched the stage-2 image SHA-256 `1ecbe9b09619221556d16fa36427655ca2593ab13b2e4fd7c9b79334c45d03a1`.

- The user reports that normal boots and cold boots passed **many times**, and that **offline memtest86 passed**. Exact boot-cycle counts, memory-test pass count, duration, executable version and test configuration were not supplied. Do not interpret this as a numerically verified ten-cycle campaign or four-pass result.
- Linux boot evidence confirms a post-flash boot with the same PCI inventory and four populated 16 GB DIMMs. The reviewed kernel log has no matching machine-check, corrected/uncorrected-memory or I/O errors; captured EDAC corrected/uncorrected error counters are zero.
- **R01's physical reporting result is observed:** all four DIMMs now report **72 total bits / 64 data bits**, replacing the previous 72/72 fields. This does not establish or change active ECC correction policy.
- The boot logger retained one distinct stage-2 Linux boot at the review time; additional user-reported POST cycles and an offline memory test need not produce Linux captures. No warm/cold count is inferred from that logger.

These are successful boot and memory-test compatibility observations for this cumulative image on this board. They do not separately validate every member's exceptional reset/SMM paths, every peripheral/wake function, other hardware configurations, or repair of the historical intermittent boot failure. No further firmware changes were made to collect these observations.

## MR9A breadcrumb diagnostic revision 2 — 2026-11-08

Revision 2 of the separate checkpoint diagnostic was added to the same stage-2
bundle. Two fresh full-chip backups matched; the image preserved current NVRAM
settings and changed only 173 bytes across three 4 KiB sectors. Flashrom verified
the write, and a separate full-chip readback exactly matched image SHA-256
`105d05288932ec504e88858d95da78af0c6be1d9068de981494d81db6fd62ed6`.
The diagnostic UncoreInitPeim SHA-256 is
`ded3a8f93fd49b9b684ed4b1dd3499eb4e0344aa21fade512baa4e58c1c46666`.

After the user reported rebooting, a new Linux boot ID was observed and the
read-only CMOS reader returned state `A1`: armed, slot 0, pass ended,
**`BF/00 location 0000`**, failed-pass count **0**, no stored failed pass. This
demonstrates that the firmware hook recorded a completed MRC pass and Linux
could read it after boot. All four 16 GB DIMMs retained their baseline widths
(72 total / 64 data bits) and 2400 MT/s configuration; PCI inventory matched
exactly. Both controllers' EDAC corrected/uncorrected counters were zero, and
the captured kernel log had no matching hardware, memory or I/O error lines.
Kernel MemTotal differed by 4 KiB; installed DIMM capacity remained 64 GB.

This is **one initial boot and successful-pass logging observation**. It does
not validate a cold boot, failed-pass freezing or retention across recovery,
every setup setting, memory stability under a new test, or repair of the
intermittent boot fault. The earlier stage-2 memory-test report predates this
diagnostic. No additional reboot, CMOS-data write or firmware write was made
while collecting the post-boot observations.

### Subsequent all-DIMMs-removed test

The user removed all four DIMMs and observed POST **`53`**. They explicitly
report **no CMOS clear and no battery removal**. After RAM was restored, a second
distinct post-flash Linux boot was observed. The raw `E0`–`E9` layout was
identical to the first successful boot: `A1`, slot 0 containing `BF000000`, slot
1 all `FF`, counter zero. No failed checkpoint was available. All four 16 GB
DIMMs, their 72/64-bit widths and 2400 MT/s configuration were restored; PCI
inventory matched, EDAC counters were zero, and no matching kernel hardware/
memory/I/O error lines appeared in the captured recovery boot.

This is a **negative result for capture of that no-RAM attempt**. It does not
validate failed-pass freezing/retention. No CMOS snapshot exists from the halted
attempt, so the evidence cannot distinguish a bypassed logging start/hook,
inaccessible storage at that phase, or later overwrite/reset/rearming. Intentional
CMOS clearing is excluded by the user's report; the root cause remains unresolved.
The no-RAM halt does not reproduce or establish the cause of the intermittent
`b0`/`b7` fault. No diagnostic code or flashed firmware was changed for this test.
