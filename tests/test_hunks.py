import unittest

from x99fix import hunks as H


def row(offset, before, after, **extra):
    return dict(offset=offset, before=before, after=after, **extra)


class ApplyTests(unittest.TestCase):
    def test_apply_then_reverse_restores_the_original(self):
        data = bytes(range(32))
        hunks = [row(4, "04", "ff"), row(10, "0a0b", "0c")]
        fixed = H.apply(data, hunks)
        self.assertEqual(fixed[4], 0xFF)
        self.assertEqual(len(fixed), 31)
        self.assertEqual(H.apply(fixed, hunks, reverse=True), data)

    def test_apply_appends_at_the_end(self):
        data = b"abc"
        self.assertEqual(H.apply(data, [row(3, "", "6465")]), b"abcde")

    def test_guard_mismatch_names_expected_and_received_bytes(self):
        with self.assertRaisesRegex(H.HunkError, r"hunk at 0x1: expected 00 \| received 01"):
            H.apply(b"\x00\x01", [row(1, "00", "02")])

    def test_overlapping_hunks_are_rejected(self):
        with self.assertRaisesRegex(H.HunkError, "overlaps"):
            H.apply(bytes(8), [row(0, "0000", "0101"), row(1, "00", "02")])

    def test_independent_hunk_lists_commute(self):
        data = bytes(range(64))
        a, b = [row(3, "03", "aa")], [row(40, "28", "bb")]
        self.assertEqual(H.apply(H.apply(data, a), b), H.apply(H.apply(data, b), a))


class StateTests(unittest.TestCase):
    def test_state_reports_original_fixed_and_mixed(self):
        data = bytes(range(16))
        hunks = [row(1, "01", "ff"), row(5, "05", "ee")]
        self.assertEqual(H.state(data, hunks), H.ORIGINAL)
        self.assertEqual(H.state(H.apply(data, hunks), hunks), H.FIXED)
        self.assertEqual(H.state(H.apply(data, hunks[:1]), hunks), H.MIXED)
        self.assertEqual(H.state(bytes(16), hunks), H.MISMATCH)


class SignatureTests(unittest.TestCase):
    def test_find_unique_rejects_repeats_and_honours_wildcards(self):
        self.assertIsNone(H.find_unique(b"xyxy", b"xy"))
        self.assertEqual(H.find_unique(b"..a1b..", b"a?b", wild=[1]), 2)

    def test_locate_finds_a_hunk_moved_in_another_build(self):
        hunk = row(0, "c3", "90", context_before="5589e5", context_after="e8000000")
        other = b"\x00" * 50 + bytes.fromhex("5589e5c3e8000000") + b"\x00" * 50
        self.assertEqual(H.locate(other, [hunk]), (H.ORIGINAL, [53]))
        patched = other[:53] + b"\x90" + other[54:]
        self.assertEqual(H.locate(patched, [hunk])[0], H.FIXED)


if __name__ == "__main__":
    unittest.main()
