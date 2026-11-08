"""Parse and rebuild UEFI PI firmware volumes, files and sections.

Only the structures these AMI Aptio images use are supported: FFSv2/FFSv3
volumes, ordinary and extended section headers, LZMA and CRC32 GUID-defined
sections and nested firmware-volume sections. Anything else is kept as opaque
bytes and is never rewritten.

Example:
    image = Path("bios.bin").read_bytes()
    for volume in find_volumes(image):
        for file in volume.files:
            print(file.guid, file.offset)
"""

from __future__ import annotations

import lzma
import struct
import uuid
from dataclasses import dataclass, field

FFS2_GUID = "8C8CE578-8A3D-4F1C-9935-896185C32DD3"
FFS3_GUID = "5473C07A-3DCB-4DCA-BD6F-1E9689E7349A"
LZMA_GUID = "EE4E5898-3914-4259-9D6E-DC7BD79403CF"
CRC32_GUID = "FC1BCDB0-7D31-49AA-936A-A4600D9DD083"

SECTION_COMPRESSION = 0x01
SECTION_GUID_DEFINED = 0x02
SECTION_PE32 = 0x10
SECTION_TE = 0x12
SECTION_FV_IMAGE = 0x17
SECTION_RAW = 0x19

FILE_PAD = 0xF0
FFS_ATTRIB_LARGE_FILE = 0x01
FFS_ATTRIB_FIXED = 0x04
FFS_ATTRIB_CHECKSUM = 0x40


class FirmwareError(ValueError):
    """A firmware structure does not match the PI layout this tool supports."""


def guid_text(raw: bytes) -> str:
    """Format a little-endian EFI GUID; e.g. guid_text(bytes(16)) == '00000000-...'."""
    return str(uuid.UUID(bytes_le=bytes(raw))).upper()


def guid_bytes(text: str) -> bytes:
    """Encode an EFI GUID string; e.g. guid_bytes(LZMA_GUID)[:4].hex() == '98584eee'."""
    return uuid.UUID(text).bytes_le


def align(value: int, size: int) -> int:
    """Round up to a multiple of size; e.g. align(9, 8) == 16."""
    return (value + size - 1) // size * size


def checksum16_ok(data: bytes) -> bool:
    """Return True when 16-bit words sum to zero, as the FV header requires."""
    return sum(struct.unpack(f"<{len(data) // 2}H", data)) & 0xFFFF == 0


@dataclass
class Section:
    """One PI section; children are set for decoded encapsulation sections."""

    offset: int
    kind: int
    header_size: int
    raw: bytes
    children: list["Section"] | None = None
    volumes: list["Volume"] | None = None
    guid: str | None = None
    data_offset: int = 0
    decoded: bytes | None = None

    @property
    def body(self) -> bytes:
        """Bytes after the common section header."""
        return self.raw[self.header_size:]


@dataclass
class FfsFile:
    """One FFS file inside a volume buffer."""

    offset: int
    header: bytes
    body: bytes
    sections: list[Section] = field(default_factory=list)

    @property
    def guid(self) -> str:
        return guid_text(self.header[:16])

    @property
    def kind(self) -> int:
        return self.header[18]

    @property
    def attributes(self) -> int:
        return self.header[19]

    @property
    def size(self) -> int:
        return len(self.header) + len(self.body)

    @property
    def extent(self) -> int:
        return align(self.size, 8)


@dataclass
class Volume:
    """One firmware volume at offset within its containing buffer."""

    offset: int
    length: int
    header_size: int
    filesystem: str
    files: list[FfsFile]
    free_start: int


def parse_sections(stream: bytes, depth: int = 0) -> list[Section]:
    """Split a section stream; decode LZMA, CRC32 and FV-image sections."""
    if depth > 8:
        raise FirmwareError("section nesting: expected at most 8 levels")
    result, offset = [], 0
    while offset + 4 <= len(stream):
        rest = stream[offset:]
        if rest.count(0) == len(rest) or rest.count(0xFF) == len(rest):
            break
        size = int.from_bytes(stream[offset:offset + 3], "little")
        header_size = 4
        if size == 0xFFFFFF:
            size = int.from_bytes(stream[offset + 4:offset + 8], "little")
            header_size = 8
        if size < header_size or offset + size > len(stream):
            raise FirmwareError(f"section at {offset:#x}: size {size:#x} exceeds stream {len(stream):#x}")
        section = Section(offset, stream[offset + 3], header_size, stream[offset:offset + size])
        decode_section(section, depth)
        result.append(section)
        offset = align(offset + size, 4)
    return result


def decode_section(section: Section, depth: int) -> None:
    """Attach decoded children to supported encapsulation sections."""
    if section.kind == SECTION_FV_IMAGE:
        section.volumes = find_volumes(section.body, nested=True)
        return
    if section.kind != SECTION_GUID_DEFINED:
        return
    h = section.header_size
    section.guid = guid_text(section.raw[h:h + 16])
    section.data_offset = int.from_bytes(section.raw[h + 16:h + 18], "little")
    payload = section.raw[section.data_offset:]
    if section.guid == LZMA_GUID:
        try:
            section.decoded = lzma.decompress(payload, format=lzma.FORMAT_ALONE)
        except lzma.LZMAError as error:
            raise FirmwareError(f"LZMA section at {section.offset:#x}: {error}") from error
    elif section.guid == CRC32_GUID:
        section.decoded = payload
    if section.decoded is not None:
        section.children = parse_sections(section.decoded, depth + 1)


def parse_volume(buffer: bytes, offset: int) -> Volume | None:
    """Parse one FV at offset; return None when the header is not valid."""
    if offset + 56 > len(buffer) or buffer[offset + 40:offset + 44] != b"_FVH":
        return None
    length = struct.unpack_from("<Q", buffer, offset + 32)[0]
    header_size = struct.unpack_from("<H", buffer, offset + 48)[0]
    if not 56 <= header_size <= length or offset + length > len(buffer):
        return None
    if not checksum16_ok(buffer[offset:offset + header_size]):
        return None
    filesystem = guid_text(buffer[offset + 16:offset + 32])
    if filesystem not in (FFS2_GUID, FFS3_GUID):
        return Volume(offset, length, header_size, filesystem, [], offset + header_size)
    ext_offset = struct.unpack_from("<H", buffer, offset + 52)[0]
    start = offset + header_size
    if ext_offset:
        ext_size = struct.unpack_from("<I", buffer, offset + ext_offset + 16)[0]
        start = max(start, offset + ext_offset + ext_size)
    files, cursor = parse_files(buffer, align(start, 8), offset + length)
    return Volume(offset, length, header_size, filesystem, files, cursor)


def parse_files(buffer: bytes, start: int, end: int) -> tuple[list[FfsFile], int]:
    """Parse FFS files from start until erased space; return files and free start."""
    files, cursor = [], start
    while cursor + 24 <= end:
        header = buffer[cursor:cursor + 24]
        if header == b"\xff" * 24:
            break
        size = int.from_bytes(header[20:23], "little")
        header_size = 24
        if header[19] & FFS_ATTRIB_LARGE_FILE:
            if cursor + 32 > end:
                raise FirmwareError(f"FFS file at {cursor:#x}: truncated extended header")
            size = struct.unpack_from("<Q", buffer, cursor + 24)[0]
            header_size = 32
        if size < header_size or cursor + size > end:
            raise FirmwareError(f"FFS file at {cursor:#x}: size {size:#x} exceeds volume end {end:#x}")
        file = FfsFile(cursor, buffer[cursor:cursor + header_size], buffer[cursor + header_size:cursor + size])
        # State and the data-checksum byte do not participate in the header sum.
        if (sum(file.header) - file.header[17] - file.header[23]) & 0xFF:
            raise FirmwareError(f"FFS file at {cursor:#x}: invalid header checksum")
        if file.attributes & FFS_ATTRIB_CHECKSUM:
            if (sum(file.body) + file.header[17]) & 0xFF:
                raise FirmwareError(f"FFS file at {cursor:#x}: invalid data checksum")
        elif file.header[17] != 0xAA:
            raise FirmwareError(f"FFS file at {cursor:#x}: expected fixed data checksum 0xaa")
        if file.kind != FILE_PAD and file.kind not in (0x01,):
            file.sections = parse_sections(file.body)
        files.append(file)
        cursor = align(cursor + size, 8)
    return files, cursor


def find_volumes(buffer: bytes, nested: bool = False) -> list[Volume]:
    """Find every valid top-level FV in buffer, skipping ranges already claimed."""
    volumes, cursor = [], 0
    while True:
        hit = buffer.find(b"_FVH", cursor)
        if hit < 0:
            return volumes
        volume = parse_volume(buffer, hit - 40) if hit >= 40 else None
        if volume is None:
            cursor = hit + 4
            continue
        volumes.append(volume)
        cursor = volume.offset + volume.length
        if nested and not volume.length:
            return volumes


def file_checksum(header: bytearray, body: bytes) -> None:
    """Recompute FFS header and data checksums in place."""
    header[17] = (-sum(body)) & 0xFF if header[19] & FFS_ATTRIB_CHECKSUM else 0xAA
    state = header[23]
    header[16] = 0
    header[23] = 0
    header[16] = (-(sum(header) - header[17])) & 0xFF
    header[23] = state


def make_file(header: bytes, body: bytes) -> bytes:
    """Build an FFS file with the given header fields and new body."""
    header = bytearray(header)
    size = len(header) + len(body)
    if len(header) == 24:
        if size >= 0xFFFFFF:
            raise FirmwareError(f"FFS size {size:#x}: expected below 0xFFFFFF without LARGE_FILE")
        header[20:23] = size.to_bytes(3, "little")
    else:
        header[24:32] = size.to_bytes(8, "little")
    file_checksum(header, body)
    return bytes(header) + body


def section_with_body(section: Section, body: bytes) -> bytes:
    """Rebuild a section's header around a new body, keeping its header form."""
    size = section.header_size + len(body)
    header = bytearray(section.raw[:section.header_size])
    if section.header_size == 8:
        header[4:8] = size.to_bytes(4, "little")
    elif size >= 0xFFFFFF:
        raise FirmwareError(f"section size {size:#x}: needs an extended header")
    else:
        header[0:3] = size.to_bytes(3, "little")
    return bytes(header) + body


def compress_like(decoded: bytes, original: bytes) -> bytes:
    """LZMA-compress with the original stream's lc/lp/pb and dictionary size."""
    prop = original[0]
    lc, rest = prop % 9, prop // 9
    lp, pb = rest % 5, rest // 5
    dictionary = int.from_bytes(original[1:5], "little")
    best = None
    for nice in (32, 64, 128, 273):
        filters = [dict(id=lzma.FILTER_LZMA1, dict_size=dictionary, lc=lc, lp=lp, pb=pb,
                        mode=lzma.MODE_NORMAL, mf=lzma.MF_BT4, nice_len=nice)]
        packed = bytearray(lzma.compress(decoded, format=lzma.FORMAT_ALONE, filters=filters))
        packed[5:13] = len(decoded).to_bytes(8, "little")
        if best is None or len(packed) < len(best):
            best = bytes(packed)
    if lzma.decompress(best, format=lzma.FORMAT_ALONE) != decoded:
        raise FirmwareError("LZMA round trip: recompressed data does not decode to the input")
    return best
