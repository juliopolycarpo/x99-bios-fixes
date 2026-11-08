# References

The audit used these documents. They are copyrighted by their publishers and are not included here. The hashes identify the exact revisions used.

| Document | Number / revision | Source | SHA-256 |
|---|---|---|---|
| Intel Xeon E5-1600/2400/2600/4600 v3 Datasheet, Vol 2 (registers) | 330784-003 | Intel (copy used: third-party mirror, https://cdn.inet.se/pdf/5311103_2.pdf) | `d57899ecf88d677176affabcd09b078bce9789e87404879697f45bdf4f5fd3f7` |
| Intel Xeon E5-1600/2400/2600/4600 v4 Datasheet, Vol 2 (registers) | 333810-002 | https://cdrdv2.intel.com/v1/dl/getContent/333810 | `5d8cf95565dc3889b394cb1a7df0ea596df4884792ef63bad329683f2419c687` |
| Intel 8 Series/C220 Series PCH Datasheet | 328904-003 | https://www.intel.com/content/dam/www/public/us/en/documents/datasheets/8-series-chipset-pch-datasheet.pdf | `1239037e57bcfa9b753c0e0c799a32f09e9705670cd2890f183c0bed7f19ec98` |
| Nuvoton NCT5532D LPC I/O Datasheet | Rev 0.7 | https://media.digikey.com/pdf/Data%20Sheets/Nuvoton%20PDFs/NCT5532D_Rev0.7.pdf | `9c7ed1afa2d29bd039f7f591fcddaf2e63bad82853d7104867f2cf9a8c048c33` |

Public specifications, all freely available from their publishers:

- **UEFI Platform Initialization (PI) Specification, Vol 3:** firmware volume, FFS file and section formats. This is what `src/x99fix/uefi.py` implements.
- **ACPI Specification 6.x:** `_UID` types for ACPI0007 processor devices (A03), and AML `And` vs `LAnd` (A02).
- **SMBIOS Specification 3.x:** Type 17 total and data width (R01).
- **JEDEC EE1004-v (DDR4 SPD EEPROM):** the SPA0/SPA1 page-select commands behind B02–B04.
- **PE/COFF Specification (Microsoft):** base relocations, which signature masking and XIP rebasing use.
