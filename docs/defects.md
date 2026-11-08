# Defect catalog

Every finding from the audit of two boards that share an X99-derived AMI Aptio BIOS:

- **PR9**: B85 chipset. Reference dump SHA-256 `095a6f5a…75ec`.
- **MR9A**: Q87 chipset, vendor image `MNX99MR9APRO_230322`.

Both were tested with a Xeon E5-2680 v4.

**Confidence** describes how sure we are that the code does what the finding says:

- **C0**: reproduced by executing the original instructions.
- **C1**: shown by code analysis with supporting evidence.
- **C2**: plausible, not verified.
- **C3**: a lead only.

Finding confidence is separate from fix confidence. A fix can be locally correct (C1) while it remains unknown (C2) whether it changes anything on real hardware.

**Priority** ranks the lead: P1 is the most relevant to the boot and memory failures reported for these boards.

**No patch here has been tested on hardware.** Treat them as candidates.

## Defects with a patch

| Patch | Findings | Boards | Module | Packing | Summary |
|---|---|---|---|---|---|
| B02-B03 | B02, B03 (C0) | both | UncoreInitPeim (PEI) | automatic | DDR4 detector overwrites its DIMM-slot counter; Auto can read page-1 bytes as the SPD header |
| B01-B06 | B01, B06 (C0) | both | UncoreInitPeim (PEI) | automatic | SPD bus polls have no timeout; writer reports ordinary bus errors as success |
| B08 | B08 (C0) | both | UncoreInitPeim (PEI) | automatic | Fatal-error return loses EBX when training-error halt is disabled |
| B01-B04-B06-B08 | B01, B04, B06, B08 (C0) | both | UncoreInitPeim (PEI) | manual | SPD page cache updated before the page command; wrong-page bytes returned as success |
| B07-B08 | B07 (C1), B08 (C0) | both | UncoreInitPeim (PEI) | manual | iMC SMBus recovery skips retained states; callers ignore initializer errors |
| B05 | B05 (C1) | both | PlatformEarlyInit + SBPEI (PEI) | automatic | Wake classifiers skip the general-reset veto, so stale S3 status can select resume |
| S01 | S01 (C2) | PR9 | UncoreInitPeim (PEI) | automatic | Cold-boot ME DRAM-init notification also runs during S3 resume |
| S02 | S02 (C1) | PR9 | OEMSmi (SMM) | automatic | S3 callback clears PME_B0_EN after the OS set up wake |
| B09 | B09 (C0) | both | 26–27 SMM/DXE modules | automatic | Byte-wide counter scans a 64-bit table count; 256+ entries loop forever |
| B10 | B10 (C0) | both | PchSmiDispatcher (SMM) | automatic | Accepts Sx exit handlers, then calls them on entry |
| B11 | B11 (C0) | both | PchSmiDispatcher (SMM) | automatic | Copies 16 bytes from 4/8-byte dispatch contexts |
| H05 | H05 (C0) | both | SioDxeInit (DXE) | automatic | Masked Super I/O writes read the previous register instead of the target |
| R01 | R01 (C0) | both | MemorySubClass (DXE) | automatic | SMBIOS Type 17 hardcodes DIMM widths 72/72 |
| A02 | A02 (C0) | both | DSDT | automatic | `RPME` tests a register for nonzero instead of the PME bit |
| A03 | A03 (C0) | both | DSDT | automatic | ACPI0007 CPU objects use string `_UID`s |
| A07 | A07 (C0) | both | DSDT | automatic | SIO/PCI AML ignores Acquire timeouts and reads fields after Release |
| H01 | H01 (C1) | MR9A | NCT5532DPeiInit (PEI) | hold | Sets the Super I/O TEST_MODE1 bit (PR9 clears it) |
| H02 | H02 (C1) | both | NCT5532DPeiInit (PEI) | hold | Masked index-port write makes the next register target input-dependent |

**Packing:**

- **automatic**: `x99fix patch` can build it.
- **manual**: the patch grows an execute-in-place PEI module, and the PEI volume has no free space. Building it means relocating PEI modules by hand; see [manual-patching.md](manual-patching.md).
- **hold**: the defect is real, but the fix may change hardware behavior the vendor relied on. `x99fix` refuses it unless you pass `--allow-hold`.

**Combining patches:**

- B01-B04-B06-B08 contains B01-B06 and B08.
- B07-B08 contains B08.
- B04 and B07 edit the same code, so they can't be combined.
- A02, A03 and A07 all edit the same DSDT, so pick one.
- The tool enforces all of these rules.

### Memory initialization (UncoreInitPeim)

UncoreInitPeim is the memory reference code (MRC). It reads each DIMM's SPD EEPROM over the CPU's integrated-memory-controller SMBus, picks timings and trains the memory. The checkpoints it posts are `B0` (DIMM detect) through `BF` (done).

- **B01:** the iMC SMBus reader and writer wait for completion with no bound. A command whose pre-busy wait expires is still issued. A DIMM, or its thermal sensor, that holds the bus hangs the boot with the last checkpoint frozen. The fix gives every wait a 100 ms limit and issues no command after a timeout.
- **B02:** in the page-select path, an inner three-slot loop reuses the outer DIMM-slot counter, so the detector probes slot 3 instead of 0/1/2. The fix gives the inner loop its own stack slot. It is nine bytes together with B03.
- **B03:** on Auto, with no DDR4 knowledge retained, the detector can parse page-1 bytes as the SPD header. The fix selects page 0 before discovery, including on Auto. It depends on B02.
- **B04:** the page-aware accessor updates its page cache before sending the page-select command and ignores a command that didn't take effect. Later successful reads then return wrong-page bytes as valid data. The fix verifies each page change with fresh data and propagates failures. It's a large native batch that grows the module by 3,072 bytes.
- **B06:** the SPD writer returns success after an ordinary bus error, so a caller that writes four bytes can report success when later reads happen to succeed.
- **B07:** idle-controller recovery skips retained clock and reset states, and callers ignore initializer errors and carry on into discovery. This is a robustness gap, not a reproduced failure.
- **B08:** when "Halt on memory training error" is disabled, the nonlocal fatal-error return loses EBX, which changes a real caller's branch. The default setting halts instead, so stock boards don't reach this path.

### Boot mode, S3 and SMM

- **B05:** PlatformEarlyInit and SBPEI decide "S3 resume or not" without the documented general-reset veto. A stale S3 status after a general reset can select the resume path. Both modules have to be patched together.
- **S01 (PR9):** the MRC calls the cold-boot ME UMA/DRAM-init notification during S3 resume as well. MR9A's MRC already skips it there. This is a candidate cause of PR9 wake failures, not a proven one.
- **S02 (PR9):** the OEM S3 entry callback clears PME_B0_EN after the OS has set up its wake sources, which can defeat wake from internal PCH devices.
- **B09:** a byte-wide loop counter scans the UEFI configuration-table count, which is 64 bits wide. With 256 or more entries it never ends. This library code is copied into 26 (MR9A) or 27 (PR9) modules. No real table that large was observed.
- **B10:** PchSmiDispatcher accepts Sx exit-phase registrations, then calls them during entry with Phase 0, because its comparison ignores the phase. The fix returns EFI_UNSUPPORTED for exit registrations.
- **B11:** the same driver's Register reads 16 bytes from public 4/8-byte context structures. A context at the end of a page faults. The fix copies the declared public sizes.

### Super I/O (Nuvoton NCT5532D)

- **H01 (MR9A, hold):** sets TEST_MODE1 in CR2F. PR9 clears the same bit. It might be a vendor workaround, so it's held until the pin functions are known.
- **H02 (hold):** a masked read/write of the index port makes the following register target depend on its input. The apparent target, CR1C, is reserved in the datasheet, so the intended register is unknown.
- **H05:** the DXE indexed-I/O table writer reads the data port before selecting the target register. Masked writes therefore combine the previous register's value. The fix moves the existing select ahead of the read.

### Reporting and ACPI

- **R01:** SMBIOS Type 17 reports total and data width 72/72 for every populated DIMM. The fix decodes widths from the SPD byte the MRC already saved.
- **A02:** `\_SB.RPME` uses a logical AND, so it tests "register nonzero" instead of the PME bit. No current caller uses it.
- **A03:** CPU device `_UID`s are strings. ACPI requires integers for ACPI0007 objects. The fix keeps existing CPU/MADT identities.
- **A07:** SIO and PCI helper methods proceed after an `Acquire` timeout, and the PCI readers read hardware fields after `Release`. The fix waits for ownership and reads before releasing.

## Findings without a patch

| ID | Boards | What | Why no patch |
|---|---|---|---|
| H11 (P1) | both | MRC waits on the PCU mailbox (`0A014090` bit 31), the UBOX system semaphore and the VCU mailbox have no bound | A bound would turn a hang into an error, not fix the cause. Not built yet |
| H09 (P3) | both | IioInit DMI retrain waits for Link Training to clear with no timeout | A stuck DMI link also takes PCH devices down; a bound changes the symptom only |
| H10 (P3) | both | PchInitDxe root-port retrain and IOBP sideband waits have no timeout | Matches the Intel 8-series reference code |
| B12 (P3) | MR9A | MRC picks restore boot mode whenever the variable `SbWarmResetVar` exists, without SBPEI's value and capsule checks | Needs a capsule update interrupted at the wrong moment; not seen |
| H03 (P3) | MR9A | Setup lets "Memory Frequency" run 2133-rated DIMMs at 2400 with Enforce POR off | Configuration, not code. Set Auto and enable Enforce POR |
| H04 (P2) | MR9A | Linux reports inconsistent Common Clock Configuration on the GPU link | Producer not identified |
| H06 (P3) | MR9A | Smart Fan SYSFAN selects PECI Agent1 on a one-socket board | Validity not confirmed; the default is Full On |
| H07 (P3) | both | Super I/O table writes registers the chip doesn't have | No-ops in the documented model |
| A01 (P2) | MR9A | GPE/GPIO resource overlap restricts `gpio_ich` | Intended ownership unknown |
| A04, A05 (P3) | MR9A | FADT denies OS ASPM control; DMAR opts out of x2APIC | Policy, not a proven defect |
| A06 (P3) | MR9A | AML queries `_OSI("Linux")` | Linux ignores it |
| A08 (P3) | both | AcpiPlatform copies an installed DSDT over the FV DSDT with no destination bound; scans read 4–7 bytes past the end | No trigger observed |
| D01 (P3) | both | NVRAM resets on store damage or a Setup size mismatch | Intended AMI behavior |

## Minor gaps (no patch, not expected to cause failures)

- **M01:** the DMI LNKCAP ASPM field is written as `10b`, which the Vol 2 notation lists as reserved. It means L1-only, which matches policy.
- **M02:** the DMI routine overwrites the negotiated width and speed without checking Data Link Layer Active.
- **M03:** the DMI Enter Compliance and Selectable De-emphasis bits come from setup. Every stored setup has them off.
- **M04:** the root-port retrain toggles Link Disable on a 10 s timeout and doesn't report whether the link came back.
- **M05:** PCH SMBus timeouts don't set HCTL KILL, so a stuck transaction keeps HOST_BUSY set.
- **M06:** the PCH SMBus driver doesn't wait on HOST_BUSY, and its byte-by-byte read tail doesn't wait for INTR.
- **M07:** the PCH SMBus block process call doesn't check the size of the caller's buffer.
- **M08:** the IOBP busy waits have no timeout (see H10).
- **M09:** an IioInit handshake on uncore offsets `87058`/`8705C` has no timeout. Neither register is in the public Vol 2.
- **M10:** the DMI retrain writes Retrain Link twice in a row. Redundant, not harmful.
- **M11:** IioInit writes per-port register `438`, which isn't in the public Vol 2.

Register references are to Intel Xeon E5 v3/v4 datasheet Vol 2 and the Intel 8-series PCH datasheet; see [references.md](references.md).
