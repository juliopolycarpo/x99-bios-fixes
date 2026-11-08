# POST codes on these boards

These sequences were read frame by frame from camera captures of the MR9A's two-digit display. On a seven-segment display, `6` has a top segment and `b` doesn't, so `b0`/`b7` are easy to misread as `60`/`67`.

| Condition | Sequence | Result |
|---|---|---|
| Normal power-on | FF b0 19 AF b0 b1 b6 b7 bd b9 bA bF 33 32 4F (8A or BA) 98 68 78 79 91 96 97 99 9C b4 A2 Ad AA | Boots |
| Shutdown | AA 72 FF | Off |
| No GPU | as normal through 4F, then 78 79 78 91 96 99 9C b4 d6 (beeps) Ad AA | Boots headless |
| No DIMMs | FF b0 53 | Halts, no beep |
| Known failure | stuck on `b7`, or on `b0` | Fans spin, no NIC LED |

## What the codes mean

- `19`: PEI before memory.
- `AF`: a warm reset during the first pass (the MRC sets it up; it's normal).
- `B0`–`BF`: Intel memory reference code checkpoints:
  - `B0`: DIMM detect.
  - `B1`: frequency.
  - `B6`: JEDEC init.
  - `B7`: training.
  - `BD`, `B9`, `BA`: later MRC steps.
  - `BF`: MRC done.
- `33`/`32`: CPU init after memory.
- `4F`: DXE IPL.
- `53`: no usable memory. The MRC's error E8 is mapped to AMI code `53`.
- `d6`: no console output device.
- `Ad`: ready to boot.
- `AA`: OS has taken over (ACPI).

## The `b0`/`b7` failure

This failure is widely reported for these boards. The board stops on `b7`, sometimes right after power-on, or on `b0` after a DIMM or GPU change. It often follows an OS freeze. The audit found the following:

- **A training failure halts with the display frozen.** With "Halt on memory training error" enabled (the default), the MRC spins and port 80 keeps `b7`. It doesn't cycle back to `b0` by itself.
- **No MRC task posted under `B7` requests a reset.** A self-cycling loop would need an outside reset.
- **Every boot does full training.** Fast boot is off in the stored setup, so saved training data isn't used.
- **No PEI module drives the speaker.** A beep at `b0`/`b7` comes from DXE code or from the hardware.
- **The halt stops the PCH TCO watchdog before the MRC runs.** The OC watchdog only covers the Intel reference recovery after an unexpected reset.

On the tested MR9A, the stuck state also survives these:

- A CMOS clear.
- A full AC drain.
- Forced 2133 MT/s.
- Different (desktop) DIMMs.

It moves when a DIMM or the GPU is moved; USB and SATA changes don't affect it. No firmware state found in the audit survives an AC drain and reacts to a GPU change. On that board, a physical cause ranks first: socket contact, cooler pressure, board flex or power delivery.

The SPD defects (B01–B04) and the unbounded mailbox waits (H11) can still turn a marginal hardware condition into a hang instead of an error. B01-B06 is the patch that would show this: with it, a stuck SPD bus produces an error code where the stock firmware freezes on `b0`.
