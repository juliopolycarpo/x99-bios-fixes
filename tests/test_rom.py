import os
import unittest
from pathlib import Path
from unittest.mock import patch

from fakes import (DXE_GUID, NEXT_GUID, FakeCatalog, FakeFirmware, component, hunk, module,
                   record, standard_records)
from x99fix.records import Record, SelectionError, load_catalog, resolve
from x99fix.rom import Rom, build, scan
from x99fix.uefi import FirmwareError, checksum16_ok, find_volumes, make_file


class FirmwareCase(unittest.TestCase):
    def setUp(self):
        self.fw = FakeFirmware()
        self.fake = FakeCatalog(standard_records(self.fw))
        self.catalog = load_catalog(self.fake.path)
        self.rom = Rom(self.fw.image)

    def tearDown(self):
        self.fake.close()

    def states(self, image):
        return {rid: row["state"] for rid, row in scan(Rom(image), self.catalog, "fake")["records"].items()}


class ScanTests(FirmwareCase):
    def test_parser_finds_both_volumes_with_valid_checksums(self):
        volumes = find_volumes(self.fw.image)
        self.assertEqual([v.offset for v in volumes], [0x1000, 0x5000])
        self.assertTrue(all(checksum16_ok(self.fw.image[v.offset:v.offset + v.header_size]) for v in volumes))

    def test_unpatched_image_reports_every_defect_present(self):
        self.assertEqual(set(self.states(self.fw.image).values()), {"present"})

    def test_board_is_detected_from_original_modules(self):
        self.assertEqual(scan(self.rom, self.catalog)["board"], "fake")


class BuildTests(FirmwareCase):
    def test_corrupt_unselected_file_prevents_build(self):
        damaged = bytearray(self.fw.image)
        file = self.rom.volumes[0].files[0]
        damaged[file.offset + 16] ^= 1
        with self.assertRaisesRegex(FirmwareError, "header checksum"):
            build(Rom(bytes(damaged)), self.catalog, ["PA"], "fake")

    def test_output_is_rejected_if_rebuilt_file_has_a_bad_checksum(self):
        def damaged_file(header, body):
            result = bytearray(make_file(header, body))
            result[16] ^= 1
            return bytes(result)
        with patch("x99fix.rom.make_file", side_effect=damaged_file):
            with self.assertRaisesRegex(FirmwareError, "header checksum"):
                build(self.rom, self.catalog, ["PA"], "fake")

    def test_subset_of_an_installed_superset_is_fixed_and_a_noop(self):
        first, _ = build(self.rom, self.catalog, ["PS"], "fake")
        self.assertEqual(self.states(first)["PA"], "fixed")
        again, _ = build(Rom(first), self.catalog, ["PA"], "fake")
        self.assertEqual(again, first)
        combined, _ = build(self.rom, self.catalog, ["PS", "PB"], "fake")
        stepped, _ = build(Rom(first), self.catalog, ["PA", "PB"], "fake")
        self.assertEqual(combined, stepped)

    def test_transitive_supersets_are_applied_once_and_report_all_fixes(self):
        source = self.catalog["PS"].components("fake")[0]
        hs = source["hunks"] + [hunk(self.fw.peim, 180, b"\x12")]
        top = record("PT", [component("Peim", source["ffs_guid"], self.fw.peim, hs)], supersedes=["PS"])
        self.catalog["PT"] = Record(top)
        together, _ = build(self.rom, self.catalog, ["PA", "PS", "PT"], "fake")
        for rid in ("PA", "PS", "PT"):
            self.assertEqual(self.states(together)[rid], "fixed")
        again, _ = build(Rom(together), self.catalog, ["PA", "PS"], "fake")
        self.assertEqual(together, again)

    def test_disjoint_patches_compose_in_any_order_and_stepwise(self):
        both, _ = build(self.rom, self.catalog, ["PA", "PB"], "fake")
        reverse, _ = build(self.rom, self.catalog, ["PB", "PA"], "fake")
        first, _ = build(self.rom, self.catalog, ["PA"], "fake")
        stepwise, _ = build(Rom(first), self.catalog, ["PB"], "fake")
        self.assertEqual(both, reverse)
        self.assertEqual(both, stepwise)
        states = self.states(both)
        self.assertEqual((states["PA"], states["PB"]), ("fixed", "fixed"))

    def test_in_place_patch_changes_only_hunk_bytes(self):
        image, _ = build(self.rom, self.catalog, ["PA"], "fake")
        changed = [i for i, (a, b) in enumerate(zip(self.fw.image, image)) if a != b]
        self.assertEqual(len(changed), 2)

    def test_superset_replaces_a_fix_already_in_the_rom(self):
        first, _ = build(self.rom, self.catalog, ["PA"], "fake")
        upgraded, _ = build(Rom(first), self.catalog, ["PS"], "fake")
        self.assertEqual(self.states(upgraded)["PS"], "fixed")

    def test_conflicting_fix_already_in_the_rom_is_refused(self):
        first, _ = build(self.rom, self.catalog, ["PB"], "fake")
        with self.assertRaisesRegex(SelectionError, "already contains PB"):
            build(Rom(first), self.catalog, ["CX"], "fake")

    def test_growing_dxe_driver_moves_following_files(self):
        image, manifest = build(self.rom, self.catalog, ["DG"], "fake")
        self.assertTrue(any(NEXT_GUID in note for note in manifest["notes"]))
        self.assertEqual(self.states(image)["DG"], "fixed")
        self.assertEqual(image[0x5000:], self.fw.image[0x5000:])

    def test_growth_that_would_move_an_xip_peim_is_refused(self):
        fw = FakeFirmware(follower_kind=0x06)
        fake = FakeCatalog([record("DG", [component("Driver", DXE_GUID, fw.driver, standard_records(fw)[3]
                                                    ["boards"]["fake"]["components"][0]["hunks"])])])
        try:
            with self.assertRaisesRegex(SelectionError, "PEI-phase image .* executes in place"):
                build(Rom(fw.image), load_catalog(fake.path), ["DG"], "fake")
        finally:
            fake.close()

    def test_growth_beyond_free_space_is_refused(self):
        fw = FakeFirmware(dxe_length=0x2000)
        fake = FakeCatalog(standard_records(fw))
        try:
            with self.assertRaisesRegex(SelectionError, "more bytes than its free space"):
                build(Rom(fw.image), load_catalog(fake.path), ["DG"], "fake")
        finally:
            fake.close()

    def test_acpi_table_patch_round_trips(self):
        image, _ = build(self.rom, self.catalog, ["TB"], "fake")
        self.assertEqual(self.states(image)["TB"], "fixed")

    def test_module_from_another_build_is_refused(self):
        other = self.fw.image.replace(self.fw.peim[:32], module(7)[:32])
        with self.assertRaisesRegex(SelectionError, "differs from the fake original"):
            build(Rom(other), self.catalog, ["PA"], "fake")


class ResolveTests(FirmwareCase):
    def test_superseded_selection_is_dropped_with_a_note(self):
        records, notes = resolve(self.catalog, ["PA", "PS"], "fake")
        self.assertEqual([r.id for r in records], ["PS"])
        self.assertIn("PA dropped", notes[0])

    def test_conflicts_hold_and_unknown_ids_are_refused(self):
        with self.assertRaisesRegex(SelectionError, "conflicts"):
            resolve(self.catalog, ["PB", "CX"], "fake")
        with self.assertRaisesRegex(SelectionError, "on hold"):
            resolve(self.catalog, ["HD"], "fake")
        self.assertEqual(len(resolve(self.catalog, ["HD"], "fake", allow_hold=True)[0]), 1)
        with self.assertRaisesRegex(SelectionError, r"patch ids \['ZZ'\]"):
            resolve(self.catalog, ["ZZ"], "fake")


@unittest.skipUnless(os.environ.get("X99FIX_ROM_MR9A") or os.environ.get("X99FIX_ROM_PR9"),
                     "set X99FIX_ROM_MR9A / X99FIX_ROM_PR9 to a stock dump to run")
class RealRomTests(unittest.TestCase):
    """Build every record alone and the recommended pair on real dumps."""

    MANUAL = {"B01-B04-B06-B08", "B07-B08"}  # grow an XIP PEIM in a full PEI volume

    def test_each_record_builds_alone_and_reports_fixed(self):
        catalog = load_catalog()
        for board in ("mr9a", "pr9"):
            path = os.environ.get(f"X99FIX_ROM_{board.upper()}")
            if not path:
                continue
            rom = Rom(Path(path).read_bytes())
            for rid, item in catalog.items():
                if not item.board(board).get("applicable"):
                    continue
                with self.subTest(board=board, record=rid):
                    if rid in self.MANUAL:
                        with self.assertRaisesRegex(SelectionError, "executes in place"):
                            build(rom, catalog, [rid], board, allow_hold=True)
                        continue
                    image, _ = build(rom, catalog, [rid], board, allow_hold=True)
                    self.assertEqual(scan(Rom(image), catalog, board)["records"][rid]["state"], "fixed")


if __name__ == "__main__":
    unittest.main()
