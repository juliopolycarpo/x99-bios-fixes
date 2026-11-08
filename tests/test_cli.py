import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from fakes import PEIM_GUID, FakeCatalog, FakeFirmware, standard_records
from x99fix import cli


class CliTests(unittest.TestCase):
    def setUp(self):
        self.fw = FakeFirmware()
        self.fake = FakeCatalog(standard_records(self.fw))
        os.environ["X99FIX_PATCHES"] = str(self.fake.path)
        self.tmp = tempfile.TemporaryDirectory()
        self.rom = Path(self.tmp.name) / "fake.bin"
        self.rom.write_bytes(self.fw.image)
        from x99fix import records
        self.saved, records.PATCH_DIR = records.PATCH_DIR, self.fake.path
        cli.load_catalog.__defaults__ = (self.fake.path,)

    def tearDown(self):
        from x99fix import records
        records.PATCH_DIR = self.saved
        cli.load_catalog.__defaults__ = (self.saved,)
        os.environ.pop("X99FIX_PATCHES", None)
        self.fake.close()
        self.tmp.cleanup()

    def run_cli(self, *argv):
        out = io.StringIO()
        with redirect_stdout(out):
            code = cli.main([str(a) for a in argv])
        return code, out.getvalue()

    def test_scan_json_reports_states(self):
        code, text = self.run_cli("scan", self.rom, "--json")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(text)["records"]["PA"]["state"], "present")

    def test_patch_writes_image_and_manifest_and_never_overwrites(self):
        out = Path(self.tmp.name) / "fixed.bin"
        self.assertEqual(self.run_cli("patch", self.rom, "--select", "recommended", "-o", out)[0], 0)
        manifest = json.loads((out.parent / "fixed.bin.manifest.json").read_text())
        self.assertEqual(manifest["patches"], ["PA", "PB"])
        self.assertEqual(self.run_cli("patch", self.rom, "--select", "PA", "-o", out)[0], 1)

    def test_extract_and_replace_round_trip_a_module(self):
        module = Path(self.tmp.name) / "peim.pe"
        self.run_cli("extract", self.rom, "--guid", PEIM_GUID, "-o", module)
        self.assertEqual(module.read_bytes(), self.fw.peim)
        edited = Path(self.tmp.name) / "edited.pe"
        edited.write_bytes(b"\x90" + self.fw.peim[1:])
        out = Path(self.tmp.name) / "replaced.bin"
        self.assertEqual(self.run_cli("replace", self.rom, "--guid", PEIM_GUID, "--input", edited, "-o", out)[0], 0)
        again = Path(self.tmp.name) / "again.pe"
        self.run_cli("extract", out, "--guid", PEIM_GUID, "-o", again)
        self.assertEqual(again.read_bytes(), edited.read_bytes())


if __name__ == "__main__":
    unittest.main()
