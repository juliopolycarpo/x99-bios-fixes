import lzma
import struct
import unittest

from x99fix.pe import branch_fields, relocation_offsets
from x99fix.uefi import compress_like, make_file


def tiny_pe(fixup_rva: int) -> bytes:
    """Return a minimal PE32 with one section and one HIGHLOW relocation."""
    data = bytearray(0x400)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x40)
    data[0x40:0x44] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x44, 0x14C, 1, 0, 0, 0, 0xE0, 0)
    opt = 0x58
    struct.pack_into("<H", data, opt, 0x10B)
    struct.pack_into("<I", data, opt + 56, 0x400)  # SizeOfImage
    struct.pack_into("<II", data, opt + 96 + 5 * 8, 0x300, 10)  # reloc directory
    table = opt + 0xE0
    data[table:table + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", data, table + 8, 0x200, 0x200, 0x200, 0x200)
    struct.pack_into("<IIH", data, 0x300, 0, 10, (3 << 12) | fixup_rva)
    return bytes(data)


class PeTests(unittest.TestCase):
    def test_relocation_offsets_cover_the_fixup_dword(self):
        self.assertEqual(relocation_offsets(tiny_pe(0x210)), {0x210, 0x211, 0x212, 0x213})

    def test_branch_fields_mask_rel32_displacements(self):
        self.assertEqual(branch_fields(bytes.fromhex("90e801020304")), {2, 3, 4, 5})
        self.assertEqual(branch_fields(bytes.fromhex("0f8401020304")), {2, 3, 4, 5})


class UefiTests(unittest.TestCase):
    def test_make_file_writes_valid_header_checksum(self):
        header = bytes(16) + bytes((0, 0, 7, 0)) + bytes(3) + b"\xf8"
        data = make_file(header, b"body")
        self.assertEqual((sum(data[:24]) - data[17] - data[23]) & 0xFF, 0)
        self.assertEqual(data[17], 0xAA)

    def test_compress_like_keeps_properties_and_round_trips(self):
        filters = [dict(id=lzma.FILTER_LZMA1, dict_size=1 << 20, lc=3, lp=0, pb=2)]
        original = lzma.compress(b"x" * 1000, format=lzma.FORMAT_ALONE, filters=filters)
        packed = compress_like(b"y" * 1000, original)
        self.assertEqual(packed[:5], original[:5])
        self.assertEqual(lzma.decompress(packed, format=lzma.FORMAT_ALONE), b"y" * 1000)


if __name__ == "__main__":
    unittest.main()
