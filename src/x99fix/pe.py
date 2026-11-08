"""Minimal PE helpers: section mapping and base-relocation fixup positions.

Example:
    offsets = relocation_offsets(Path("UncoreInitPeim.pe").read_bytes())
"""

from __future__ import annotations

import struct


def sections(pe: bytes) -> list[tuple[int, int, int, int]]:
    """Return (rva, virtual_size, raw_offset, raw_size) for each PE section."""
    header = struct.unpack_from("<I", pe, 0x3C)[0]
    if pe[header:header + 4] != b"PE\0\0":
        raise ValueError(f"PE header at {header:#x}: expected 'PE\\0\\0' | received {pe[header:header + 4]!r}")
    count = struct.unpack_from("<H", pe, header + 6)[0]
    optional = struct.unpack_from("<H", pe, header + 20)[0]
    table = header + 24 + optional
    rows = []
    for index in range(count):
        at = table + index * 40
        vsize, rva, rsize, raw = struct.unpack_from("<IIII", pe, at + 8)
        rows.append((rva, vsize, raw, rsize))
    return rows


def rva_to_offset(pe: bytes, rva: int) -> int | None:
    """Map an RVA to a file offset, or None when it is not backed by file data."""
    for start, vsize, raw, rsize in sections(pe):
        if start <= rva < start + max(vsize, rsize) and rva - start < rsize:
            return raw + rva - start
    return rva if rva < struct.unpack_from("<I", pe, struct.unpack_from("<I", pe, 0x3C)[0] + 84)[0] else None


def relocation_offsets(pe: bytes) -> set[int]:
    """Return file offsets of every byte covered by a HIGHLOW or DIR64 fixup."""
    header = struct.unpack_from("<I", pe, 0x3C)[0]
    wide = struct.unpack_from("<H", pe, header + 24)[0] == 0x20B
    directory = header + 24 + (112 if wide else 96) + 5 * 8
    rva, size = struct.unpack_from("<II", pe, directory)
    start = rva_to_offset(pe, rva) if size else None
    covered = set()
    if start is None:
        return covered
    cursor, end = start, start + size
    while cursor + 8 <= end:
        page, block = struct.unpack_from("<II", pe, cursor)
        if block < 8:
            break
        for (entry,) in struct.iter_unpack("<H", pe[cursor + 8:cursor + block]):
            kind, delta = entry >> 12, entry & 0xFFF
            width = {3: 4, 10: 8}.get(kind)
            target = rva_to_offset(pe, page + delta) if width else None
            if target is not None:
                covered.update(range(target, target + width))
        cursor += block
    return covered


def branch_fields(code: bytes) -> set[int]:
    """Return positions of likely rel32 branch displacements (E8/E9/0F 8x).

    This is a byte heuristic, not a disassembler: it may also mask data that
    happens to look like a branch, which only makes signatures less specific.
    """
    wild = set()
    for index, value in enumerate(code):
        if value in (0xE8, 0xE9) and index + 5 <= len(code):
            wild.update(range(index + 1, index + 5))
        elif value == 0x0F and index + 6 <= len(code) and 0x80 <= code[index + 1] <= 0x8F:
            wild.update(range(index + 2, index + 6))
    return wild
