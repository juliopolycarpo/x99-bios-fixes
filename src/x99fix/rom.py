"""Find patch components in a ROM, report defect state and build patched copies.

The ROM is never modified in place and nothing here touches hardware.

Example:
    rom = Rom(Path("dump.bin").read_bytes())
    report = scan(rom, load_catalog())
    image, manifest = build(rom, catalog, ["B02-B03"], board="mr9a")
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass, field

from . import hunks as H
from .records import Record, SelectionError, boards, resolve
from .uefi import (CRC32_GUID, FFS_ATTRIB_FIXED, FILE_PAD, LZMA_GUID, SECTION_PE32, SECTION_RAW,
                   SECTION_TE, FirmwareError, FfsFile, Section, Volume, align, compress_like,
                   find_volumes, make_file, section_with_body)

VTF_GUID = "1BA0062E-C779-4582-8566-336AE8F78F09"
ALIGNMENTS = (1, 16, 128, 512, 1024, 4096, 32768, 65536)


@dataclass
class Leaf:
    """One leaf section and the path of section indices that reaches it."""

    volume: Volume
    file: FfsFile
    path: tuple[int, ...]
    section: Section
    compressed: bool


@dataclass
class Rom:
    """A parsed firmware image (full SPI dump or BIOS region)."""

    image: bytes
    volumes: list[Volume] = field(init=False)
    leaves: dict[str, list[Leaf]] = field(init=False)

    def __post_init__(self):
        self.volumes = find_volumes(self.image)
        if not self.volumes:
            raise FirmwareError("image: expected at least one UEFI firmware volume (_FVH) | received none")
        self.leaves = {}
        for volume in self.volumes:
            for file in volume.files:
                for path, section, compressed in walk(file.sections):
                    self.leaves.setdefault(file.guid, []).append(Leaf(volume, file, path, section, compressed))


def walk(sections, prefix=(), compressed=False):
    """Yield (path, section, compressed) for every leaf in a section list."""
    for index, section in enumerate(sections):
        if section.children is not None:
            inner = compressed or section.guid == LZMA_GUID
            yield from walk(section.children, prefix + (index,), inner)
        elif not section.volumes:
            yield prefix + (index,), section, compressed


def acpi_table(body: bytes, offset: int) -> bytes:
    """Return the ACPI table whose header starts at offset in a RAW body."""
    length = struct.unpack_from("<I", body, offset + 4)[0] if len(body) >= offset + 8 else 0
    return body[offset:offset + length]


def module_bytes(leaf: Leaf, component: dict) -> bytes | None:
    """Return the component bytes a leaf holds, or None when the kind differs."""
    if component["leaf"] == "pe32":
        return leaf.section.body if leaf.section.kind in (SECTION_PE32, SECTION_TE) else None
    if leaf.section.kind != SECTION_RAW:
        return None
    table = acpi_table(leaf.section.body, component.get("table_offset", 0))
    return table if table[:4] == b"DSDT" else None


def component_key(component: dict) -> tuple[str, str]:
    return component["ffs_guid"].upper(), component["leaf"]


def hunks_by_record(catalog, board, key):
    """Map record id to its hunks on the component identified by key."""
    found = {}
    for rid, record in catalog.items():
        for component in record.components(board):
            if component_key(component) == key:
                found[rid] = (component, component["hunks"])
    return found


@dataclass
class Match:
    """A component found in the ROM and its relation to a board's original."""

    leaf: Leaf
    current: bytes
    original: bytes | None
    fixed: list[str]


def match_component(rom: Rom, catalog, board: str, component: dict) -> Match | None:
    """Locate a component and undo known fixes to recover the original build."""
    key = component_key(component)
    related = hunks_by_record(catalog, board, key)
    for leaf in rom.leaves.get(key[0], []):
        current = module_bytes(leaf, component)
        if current is None:
            continue
        fixed = [rid for rid, (_, hs) in related.items() if H.state(current, hs) == H.FIXED]
        fixed = [rid for rid in fixed
                 if not any(rid in catalog[other].data.get("supersedes", []) for other in fixed)]
        try:
            original = H.apply(current, [h for rid in fixed for h in related[rid][1]], reverse=True)
        except H.HunkError:
            continue
        if H.sha256(original) == component["source_sha256"]:
            return Match(leaf, current, original, fixed)
    return None


def detect_board(rom: Rom, catalog) -> str | None:
    """Return the board whose original components the ROM contains most of."""
    scores = {}
    for board in boards(catalog):
        seen = {component_key(c): match_component(rom, catalog, board, c)
                for record in catalog.values() for c in record.components(board)}
        scores[board] = sum(1 for item in seen.values() if item)
    best = max(scores, key=scores.get, default=None)
    return best if best and scores[best] else None


def record_state(rom: Rom, catalog, board: str, record: Record) -> dict:
    """Describe one record on the ROM: present, fixed, partial or unknown."""
    entry = record.board(board)
    if not entry.get("applicable"):
        return dict(state="not-applicable", detail=entry.get("reason", ""))
    states, missing = [], []
    for component in record.components(board):
        match = match_component(rom, catalog, board, component)
        if match is None:
            missing.append(component["name"])
            continue
        states.append("fixed" if record.id in match.fixed else "present")
    if missing:
        return dict(state="unknown-build", detail=f"not the {board} original: {', '.join(missing[:4])}")
    if set(states) == {"present"}:
        return dict(state="present", detail="defect present; patch applies to this exact build")
    if set(states) == {"fixed"}:
        return dict(state="fixed", detail="already patched")
    return dict(state="partial", detail="some components patched, some not")


def signature_scan(rom: Rom, record: Record, board: str) -> dict:
    """Look for a record's defect by context signature in any build."""
    results = []
    for component in record.components(board):
        best = H.MISMATCH
        for leaf in rom.leaves.get(component["ffs_guid"].upper(), []):
            current = module_bytes(leaf, component)
            if current is not None:
                state, _ = H.locate(current, component["hunks"])
                if state != H.MISMATCH:
                    best = state
                    break
        results.append(best)
    if results and all(r == H.ORIGINAL for r in results):
        return dict(state="likely-present", detail=f"code pattern of the {board} defect found; build differs")
    if results and all(r == H.FIXED for r in results):
        return dict(state="likely-fixed", detail="fixed code pattern found")
    return dict(state="not-detected", detail="pattern not found (different code or no such module)")


def scan(rom: Rom, catalog, board: str | None = None) -> dict:
    """Report every record's state; fall back to signatures on unknown builds."""
    board = board or detect_board(rom, catalog)
    rows = {}
    for rid, record in catalog.items():
        if board is None:
            hits = [signature_scan(rom, record, b) for b in boards(catalog) if record.components(b)]
            rows[rid] = next((h for h in hits if h["state"] != "not-detected"), hits[0] if hits else
                             dict(state="not-applicable", detail=""))
            continue
        row = record_state(rom, catalog, board, record)
        if row["state"] == "unknown-build":
            row = signature_scan(rom, record, board)
        rows[rid] = row
    return dict(board=board, records=rows)


# ---- rebuilding -----------------------------------------------------------

def rebuild_stream(sections: list[Section], stream_tail: bytes, path: tuple[int, ...], body: bytes) -> bytes:
    """Return a section stream with the leaf at path replaced by body."""
    parts = []
    for index, section in enumerate(sections):
        if index != path[0]:
            parts.append(section.raw)
        elif len(path) == 1:
            parts.append(section_with_body(section, body))
        else:
            parts.append(rebuild_encapsulation(section, path[1:], body))
    out = bytearray()
    for index, part in enumerate(parts):
        out += part
        if index + 1 < len(parts):
            out += bytes(-len(out) & 3)
    return bytes(out) + stream_tail


def stream_tail(stream: bytes, sections: list[Section]) -> bytes:
    """Return padding after the last section, kept verbatim."""
    end = sections[-1].offset + len(sections[-1].raw) if sections else 0
    return stream[align(end, 4):] if align(end, 4) < len(stream) else b""


def rebuild_encapsulation(section: Section, path: tuple[int, ...], body: bytes) -> bytes:
    """Rebuild one LZMA or CRC32 GUID-defined section around a changed child."""
    inner = rebuild_stream(section.children, stream_tail(section.decoded, section.children), path, body)
    extra = bytearray(section.raw[section.header_size:section.data_offset])
    if section.guid == LZMA_GUID:
        payload = compress_like(inner, section.raw[section.data_offset:])
    elif section.guid == CRC32_GUID:
        payload = inner
        extra[20:24] = (zlib.crc32(inner) & 0xFFFFFFFF).to_bytes(4, "little")
    else:
        raise FirmwareError(f"GUID section {section.guid}: rebuilding is not supported")
    return section_with_body(section, bytes(extra) + payload)


def rebuilt_file(leaf: Leaf, body: bytes) -> bytes:
    """Return the FFS file holding leaf with its leaf body replaced."""
    file = leaf.file
    stream = rebuild_stream(file.sections, stream_tail(file.body, file.sections), leaf.path, body)
    return make_file(file.header, stream)


def keep_extent(data: bytes, extent: int, header_size: int) -> bytes:
    """Pad a shrunk file with a RAW section so later files keep their offsets."""
    if align(len(data), 8) >= extent:
        return data
    body = data[header_size:]
    body += bytes(-len(body) & 3)
    filler = extent - header_size - len(body)
    if filler < 4:
        return data
    return make_file(data[:header_size], body + filler.to_bytes(3, "little") + bytes([SECTION_RAW]) + b"\xff" * (filler - 4))


XIP_FILE_TYPES = (0x03, 0x04, 0x06, 0x08)  # SEC, PEI core, PEIM, combined PEIM/driver


def xip_reason(file: FfsFile, flash_base: int) -> str | None:
    """Return why an uncompressed image in file runs from its flash address.

    PEI-phase file types execute in place. Any other image is treated as XIP
    only when its ImageBase equals the address it occupies in flash.
    """
    for path, section, compressed in walk(file.sections):
        if compressed or section.kind not in (SECTION_PE32, SECTION_TE):
            continue
        if file.kind in XIP_FILE_TYPES:
            return f"is a PEI-phase image (file type {file.kind:#x}) that executes in place"
        offset = sum(s_offset for s_offset in section_offsets(file, path))
        address = flash_base + file.offset + len(file.header) + offset + section.header_size
        body = section.body
        if section.kind == SECTION_TE and body[:2] == b"VZ":
            stripped = struct.unpack_from("<H", body, 6)[0]
            base = struct.unpack_from("<Q", body, 16)[0] + 40 - stripped
        elif body[:2] == b"MZ":
            pe = struct.unpack_from("<I", body, 0x3C)[0]
            wide = struct.unpack_from("<H", body, pe + 24)[0] == 0x20B
            base = struct.unpack_from("<Q" if wide else "<I", body, pe + 48 if wide else pe + 52)[0]
        else:
            continue
        if base == address:
            return f"executes in place at {address:#x} and would need relocation"
    return None


def section_offsets(file: FfsFile, path: tuple[int, ...]) -> list[int]:
    """Return the section offsets along an uncompressed path inside file."""
    offsets, sections = [], file.sections
    for index in path:
        section = sections[index]
        offsets.append(section.offset)
        sections = section.children or []
        if section.children is not None:
            offsets.append(section.data_offset)
    return offsets


def erased(body: bytes) -> bool:
    """Return True when body is empty or all 0xFF (an erased PAD payload)."""
    return body.count(0xFF) == len(body)


def movable(file: FfsFile, flash_base: int) -> str | None:
    """Return why a file must not move, or None when moving it is safe."""
    if file.attributes & FFS_ATTRIB_FIXED:
        return "has the FIXED attribute"
    if file.guid == VTF_GUID:
        return "is the volume top file"
    if file.attributes & 0x02:
        return "uses FFSv3 extended data alignment"
    reason = xip_reason(file, flash_base)
    if reason:
        return reason
    if file.kind == FILE_PAD and erased(file.body) is False:
        return "is a PAD file that carries data"
    return None


def pad_file(size: int) -> bytes:
    """Return an erased PAD file of size bytes (a multiple of 8, at least 24)."""
    header = b"\xff" * 16 + bytes((0, 0xAA, FILE_PAD, 0)) + size.to_bytes(3, "little") + b"\xf8"
    return make_file(header, b"\xff" * (size - 24))


def place(cursor: int, original: int, file: FfsFile) -> int:
    """Return the first legal start at or after both cursor and the original offset.

    The gap left after cursor must be zero or hold a PAD file (24+ bytes), and
    the file's data must meet its declared alignment.
    """
    alignment = ALIGNMENTS[(file.attributes >> 3) & 7]
    header = 32 if file.attributes & 1 else 24
    start = align(max(cursor, original), 8)
    while (start + header) % alignment or 0 < start - cursor < 24:
        start += 8
    return start


def reflow(image: bytearray, volume: Volume, replaced: dict[int, bytes]) -> list[str]:
    """Rewrite a volume's files in order, moving later files when one grows."""
    end = volume.offset + volume.length
    out, notes = bytearray(image[volume.offset:end]), []
    base = volume.offset
    cursor = volume.files[0].offset if volume.files else volume.free_start
    out[cursor - base:] = b"\xff" * (end - cursor)
    for index, file in enumerate(volume.files):
        if file.kind == FILE_PAD and erased(file.body) and index not in replaced:
            continue
        data = replaced.get(index, file.header + file.body)
        start = place(cursor, file.offset, file)
        if start != file.offset:
            reason = movable(file, (1 << 32) - len(image))
            if reason:
                raise SelectionError(f"file {file.guid} at {file.offset:#x} {reason}; "
                                     "this patch cannot be packed automatically here")
            notes.append(f"moved {file.guid} {file.offset:#x} -> {start:#x}")
        if start > cursor:
            out[cursor - base:start - base] = pad_file(start - cursor)
        if start + len(data) > end:
            raise SelectionError(f"volume at {volume.offset:#x}: needs {start + len(data) - end:#x} more bytes "
                                 "than its free space; this patch cannot be packed automatically here")
        out[start - base:start - base + len(data)] = data
        cursor = align(start + len(data), 8)
    image[volume.offset:end] = out
    return notes


def carried_fixes(catalog, present: list[str], wanted: set[str]) -> set[str]:
    """Return fixes already in the ROM that stay; superseded ones are replaced."""
    keep = set()
    for rid in present:
        if any(rid in catalog[w].data.get("supersedes", []) for w in wanted):
            continue
        clash = [w for w in wanted if rid in catalog[w].data.get("conflicts", [])]
        if clash:
            raise SelectionError(f"ROM already contains {rid}, which conflicts with {clash}; "
                                 "start from an unpatched dump")
        keep.add(rid)
    return keep


def build(rom: Rom, catalog, ids: list[str], board: str | None = None,
          allow_hold: bool = False) -> tuple[bytes, dict]:
    """Return (patched image, manifest) for the selected record ids.

    Fixes already in the ROM are kept. Every component is rebuilt from the
    recovered original plus the union of selected and present fixes, then the
    output is re-parsed and each component re-checked.
    """
    board = board or detect_board(rom, catalog)
    if board is None:
        raise SelectionError("board: no known board's original modules were found; see docs/porting.md")
    records, notes = resolve(catalog, ids, board, allow_hold)
    wanted = {r.id for r in records}
    plan = {}
    for record in records:
        for component in record.components(board):
            match = match_component(rom, catalog, board, component)
            if match is None:
                raise SelectionError(f"{record.id}/{component['name']}: module differs from the {board} "
                                     "original this patch was made for")
            plan.setdefault(component_key(component), (component, match))
    image = bytearray(rom.image)
    by_volume: dict[int, dict[int, bytes]] = {}
    report = []
    for key, (component, match) in plan.items():
        related = hunks_by_record(catalog, board, key)
        keep = sorted(carried_fixes(catalog, match.fixed, wanted) | (wanted & set(related)))
        result = H.apply(match.original, [h for rid in keep for h in related[rid][1]])
        if len(keep) == 1 and H.sha256(result) != related[keep[0]][0]["result_sha256"]:
            raise SelectionError(f"{component['name']}: result hash differs from the published {keep[0]} result")
        leaf = match.leaf
        body = result
        if component["leaf"] == "acpi-table":
            container, at = leaf.section.body, component.get("table_offset", 0)
            body = container[:at] + result + container[at + len(match.current):]
        data = rebuilt_file(leaf, body)
        header = len(leaf.file.header)
        data = keep_extent(data, leaf.file.extent, header)
        volume_index = rom.volumes.index(leaf.volume)
        file_index = leaf.volume.files.index(leaf.file)
        by_volume.setdefault(volume_index, {})[file_index] = data
        report.append(dict(component=component["name"], ffs_guid=key[0], patches=keep,
                           result_sha256=H.sha256(result), file_offset=hex(leaf.file.offset),
                           file_size_change=align(len(data), 8) - leaf.file.extent))
    for volume_index, replaced in by_volume.items():
        volume = rom.volumes[volume_index]
        grows = any(align(len(d), 8) > volume.files[i].extent for i, d in replaced.items())
        if grows:
            notes += reflow(image, volume, replaced)
            continue
        for file_index, data in replaced.items():
            file = volume.files[file_index]
            image[file.offset:file.offset + file.extent] = data + b"\xff" * (file.extent - len(data))
    patched = bytes(image)
    check = Rom(patched)
    for rid in wanted:
        state = record_state(check, catalog, board, catalog[rid])["state"]
        if state != "fixed":
            raise SelectionError(f"{rid}: re-parsed output shows state {state!r} | expected 'fixed'")
    touched = [rom.volumes[i] for i in by_volume]
    for start, stop in outside(len(patched), touched):
        if patched[start:stop] != rom.image[start:stop]:
            raise SelectionError(f"bytes {start:#x}-{stop:#x} outside the patched volumes changed")
    manifest = dict(board=board, patches=sorted(wanted), notes=notes, components=report,
                    input_sha256=H.sha256(rom.image), output_sha256=H.sha256(patched),
                    hardware_tested=False)
    return patched, manifest


def outside(size: int, volumes: list[Volume]) -> list[tuple[int, int]]:
    """Return byte ranges of the image not covered by the given volumes."""
    ranges, cursor = [], 0
    for volume in sorted(volumes, key=lambda v: v.offset):
        if volume.offset > cursor:
            ranges.append((cursor, volume.offset))
        cursor = max(cursor, volume.offset + volume.length)
    if cursor < size:
        ranges.append((cursor, size))
    return ranges
