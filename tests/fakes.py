"""Named fakes: synthetic firmware volumes, files, sections and patch records.

They follow the PI layout closely enough for the parser and packer, and hold
no vendor code.
"""

from __future__ import annotations

import hashlib
import json
import lzma
import struct
import tempfile
from pathlib import Path

from x99fix.hunks import apply, sha256
from x99fix.uefi import FFS2_GUID, LZMA_GUID, align, guid_bytes, make_file

PEIM_GUID = "11111111-2222-3333-4444-555555555555"
DXE_GUID = "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"
NEXT_GUID = "99999999-8888-7777-6666-555555555555"
PAD_GUID = "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF"
TABLE_GUID = "7E374E25-8E01-4FEE-87F2-390C23C606CD"


def section(kind: int, body: bytes) -> bytes:
    """Return a section with a common four-byte header."""
    return (4 + len(body)).to_bytes(3, "little") + bytes([kind]) + body


def lzma_section(stream: bytes) -> bytes:
    """Return an LZMA GUID-defined section wrapping a section stream."""
    filters = [dict(id=lzma.FILTER_LZMA1, dict_size=1 << 16, lc=3, lp=0, pb=2)]
    packed = bytearray(lzma.compress(stream, format=lzma.FORMAT_ALONE, filters=filters))
    packed[5:13] = len(stream).to_bytes(8, "little")
    header = guid_bytes(LZMA_GUID) + (24).to_bytes(2, "little") + (1).to_bytes(2, "little")
    return section(0x02, header + bytes(packed))


def ffs(guid: str, kind: int, body: bytes, attributes: int = 0) -> bytes:
    """Return an FFS file with valid checksums."""
    header = guid_bytes(guid) + bytes((0, 0, kind, attributes)) + bytes(3) + b"\xf8"
    return make_file(header, body)


def volume(files: list[bytes], length: int = 0x4000) -> bytes:
    """Return an FFSv2 volume holding files in order, erased to length."""
    header = bytearray(bytes(16) + guid_bytes(FFS2_GUID) + struct.pack("<Q", length) + b"_FVH")
    header += struct.pack("<IHHHBB", 0x0004FEFF, 0x48, 0, 0, 0, 2)
    header += struct.pack("<IIII", length // 0x1000, 0x1000, 0, 0)
    header[50:52] = ((-sum(struct.unpack("<36H", header))) & 0xFFFF).to_bytes(2, "little")
    out = bytearray(header)
    for file in files:
        out += b"\xff" * (align(len(out), 8) - len(out))
        out += file
    return bytes(out) + b"\xff" * (length - len(out))


def module(seed: int, size: int = 256) -> bytes:
    """Return deterministic non-PE module bytes with no repeated windows."""
    return bytes((seed * 7 + i * 31 + (i >> 8) * 13) & 0xFF for i in range(size))


def noise(size: int) -> bytes:
    """Return deterministic incompressible bytes from a SHA-256 chain."""
    out, block = bytearray(), b"seed"
    while len(out) < size:
        block = hashlib.sha256(block).digest()
        out += block
    return bytes(out[:size])


def acpi(body: bytes) -> bytes:
    """Return a fake ACPI DSDT table with a correct length field."""
    return b"DSDT" + struct.pack("<I", 36 + len(body)) + bytes(28) + body


class FakeFirmware:
    """A small image: a PEI volume (XIP PEIM) and a DXE volume (LZMA driver + DSDT)."""

    def __init__(self, dxe_length: int = 0x4000, follower_kind: int = 0x07):
        self.peim = module(1)
        self.driver = module(2, 512)
        self.table = acpi(module(3, 96))
        pei = volume([ffs(PEIM_GUID, 0x06, section(0x10, self.peim))])
        dxe_files = [
            ffs(DXE_GUID, 0x07, lzma_section(section(0x10, self.driver))),
            ffs(PAD_GUID, 0xF0, b""),  # empty PAD header, as stock MR9A has
            ffs(NEXT_GUID, follower_kind, section(0x10, module(4, 64))),
            ffs(TABLE_GUID, 0x02, section(0x19, self.table)),
        ]
        self.image = b"\xff" * 0x1000 + volume(dxe_files, dxe_length) + pei


def hunk(data: bytes, offset: int, after: bytes, before_len: int | None = None) -> dict:
    """Return a hunk replacing data[offset:offset+len] with after, plus context."""
    length = len(after) if before_len is None else before_len
    return dict(offset=offset, before=data[offset:offset + length].hex(), after=after.hex(),
                context_before=data[max(0, offset - 16):offset].hex(),
                context_after=data[offset + length:offset + length + 16].hex())


def component(name: str, guid: str, source: bytes, hunks: list[dict], leaf: str = "pe32") -> dict:
    """Return a record component for source and hunks with computed hashes."""
    result = apply(source, hunks)
    row = dict(name=name, ffs_guid=guid, leaf=leaf, source_sha256=sha256(source), source_size=len(source),
               result_sha256=sha256(result), result_size=len(result), hunks=hunks)
    if leaf == "acpi-table":
        row["table_offset"] = 0
    return row


def record(rid: str, components: list[dict], **extra) -> dict:
    """Return a schema-1 record for board 'fake'."""
    data = dict(schema=1, id=rid, title=f"fake {rid}", findings=[rid], tier=extra.pop("tier", 2),
                supersedes=extra.pop("supersedes", []), conflicts=extra.pop("conflicts", []),
                limits="fake", boards={"fake": dict(applicable=True, components=components)})
    data.update(extra)
    return data


class FakeCatalog:
    """Write records to a temporary directory usable as X99FIX_PATCHES."""

    def __init__(self, records: list[dict]):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name)
        for item in records:
            (self.path / f"{item['id']}.json").write_text(json.dumps(item))

    def close(self):
        self.tmp.cleanup()


def standard_records(fw: FakeFirmware) -> list[dict]:
    """Records: two disjoint PEIM fixes, a superset of one, a growing DXE fix, a DSDT fix."""
    peim_a = [hunk(fw.peim, 10, b"\x90\x90")]
    peim_b = [hunk(fw.peim, 100, b"\xcc")]
    superset = peim_a + [hunk(fw.peim, 50, b"\x00\x01")]
    grow = [hunk(fw.driver, 20, b"\x11"), dict(offset=len(fw.driver), before="", after=noise(0x2400).hex(),
                                               context_before="", context_after="")]
    table = [hunk(fw.table, 40, b"\x5a")]
    return [
        record("PA", [component("Peim", PEIM_GUID, fw.peim, peim_a)], tier=1),
        record("PB", [component("Peim", PEIM_GUID, fw.peim, peim_b)], tier=1),
        record("PS", [component("Peim", PEIM_GUID, fw.peim, superset)], supersedes=["PA"]),
        record("DG", [component("Driver", DXE_GUID, fw.driver, grow)]),
        record("TB", [component("Table", TABLE_GUID, fw.table, table, leaf="acpi-table")]),
        record("HD", [component("Peim", PEIM_GUID, fw.peim, [hunk(fw.peim, 200, b"\x01")])], tier="hold"),
        record("CX", [component("Peim", PEIM_GUID, fw.peim, [hunk(fw.peim, 150, b"\x02")])], conflicts=["PB"]),
    ]
