#!/usr/bin/env python3
"""Build the reviewed MR9A breadcrumb diagnostic offline; never opens hardware.

Requires NASM. The input must contain the exact B01-B06 + B02-B03 UncoreInitPeim
at its reviewed flash address. Other firmware files are preserved byte for byte.
This diagnostic is separate from the x99fix correction catalog.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from x99fix.pe import relocation_offsets
from x99fix.rom import Rom, rebuilt_file
from x99fix.uefi import SECTION_PE32

IMAGE_BASE = 0xFFDE4DE8
GUID = 'D71C8BA4-4AF2-4D0D-B1BA-F2409F0C20D3'
SOURCE_SHA256 = '95a0d4deb0d285ee4ee9ff9f59f9533f9ea14117af27fa0972343e5806a936bd'
# The CMOS-map and enable-order conclusions depend on these surrounding modules,
# not only on the MRC's bytes. Accept the reviewed B05 and B09 variants as well.
PROFILES = {
    'CmosPei': ('654FE61A-2EDA-4749-A76A-56ED7ADE1CBE', {
        '8e6d83cfd262d0e2f340a5ebcd769416188246cabda1559cad4f299d102451eb'}),
    'CmosDxe': ('3237418A-478C-4700-B59F-768E2CCBC726', {
        '7b95ca1d9f79a74cfb7463390f78de3d7d1012b0258fcef151127bd616a6beb1',
        '7e2428bb334d0966a22c4222ea7038c282f730fae9663af8549f64129a42058d'}),
    'PlatformEarlyInit': ('EE685731-CFF3-4EE7-9388-7E63FC5A59B0', {
        'c017b4ea3d9fd60e4290c2fb591b58640a7e0f0c611c759f91ab88b88e2c95db',
        'ccd31b0572b37d95e5b499467cbb455e5632ee2b37b53b2d009ca14603fc1c05'}),
}
REGIONS = [
    ('r0', 0xFFE4276C, 30, bytes.fromhex('8b4424040fb68827210200510fb7882d0600005150e81a98fcff83c40cc3')),
    ('ra', 0xFFE613A2, 88, b'\x90' * 88),
    ('rb', 0xFFE61903, 53, b'\x90' * 53),
    ('site', 0xFFE0FEA9, 5, bytes.fromhex('e8be280300')),
]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def assemble():
    with tempfile.TemporaryDirectory() as directory:
        output = Path(directory) / 'breadcrumbs.bin'
        subprocess.run(['nasm', '-f', 'bin', '-o', str(output), str(ROOT/'tools/mrc-breadcrumbs.asm')], check=True)
        return output.read_bytes()


def component(source, code):
    """Apply only the four reviewed regions to an authenticated source PE."""
    require(digest(source) == SOURCE_SHA256, 'expected the exact MR9A B01-B06 + B02-B03 component')
    require(len(code) == sum(size for _, _, size, _ in REGIONS), 'unexpected assembled extent')
    touched = {i for _, va, size, _ in REGIONS for i in range(va-IMAGE_BASE, va-IMAGE_BASE+size)}
    require(not touched & relocation_offsets(source), 'a patched byte has a PE base relocation')
    result, cursor, hunks = bytearray(source), 0, []
    for name, va, size, before in REGIONS:
        offset = va - IMAGE_BASE
        require(source[offset:offset+size] == before, f'{name}: original bytes differ')
        after = code[cursor:cursor+size]
        result[offset:offset+size] = after
        hunks.append(dict(region=name, va=hex(va), offset=offset, before=before.hex(), after=after.hex()))
        cursor += size
    return bytes(result), hunks


def build(image, code):
    """Build a same-size ROM and verify every unselected FFS file is identical."""
    rom = Rom(image)
    profiles = {}
    for name, (guid, accepted) in PROFILES.items():
        payloads = [l.section.body for l in rom.leaves.get(guid, []) if l.section.kind == SECTION_PE32]
        require(len(payloads) == 1 and digest(payloads[0]) in accepted,
                f'{name}: expected the reviewed CMOS/early-init profile')
        profiles[name] = digest(payloads[0])
    matches = [leaf for leaf in rom.leaves.get(GUID, []) if leaf.section.kind == SECTION_PE32]
    require(len(matches) == 1, 'expected one UncoreInitPeim PE32 section')
    leaf = matches[0]
    require(not leaf.compressed and len(leaf.path) == 1, 'expected a direct uncompressed XIP section')
    source = leaf.section.body
    patched, hunks = component(source, code)
    file = leaf.file
    within_file = len(file.header) + leaf.section.offset + leaf.section.header_size
    offset = file.offset + within_file
    require(len(image) == 0x1000000 and 0xFF000000 + offset == IMAGE_BASE,
            'expected the reviewed 16 MiB MR9A flash layout and XIP address')
    require(image[offset:offset+len(source)] == source, 'PE is not at its expected physical offset')
    data = rebuilt_file(leaf, patched)
    require(len(data) == len(file.header) + len(file.body), 'diagnostic must not grow the FFS file')
    result = image[:file.offset] + data + image[file.offset+len(data):]
    output = Rom(result)  # validates all FFS checksums, including the rebuilt file
    require(len(image) == len(result), 'ROM extent changed')
    require(result[:file.offset] == image[:file.offset] and
            result[file.offset+len(data):] == image[file.offset+len(data):], 'bytes outside UncoreInitPeim changed')
    require([(v.offset, v.length, v.header_size) for v in rom.volumes] ==
            [(v.offset, v.length, v.header_size) for v in output.volumes], 'volume geometry changed')
    checked = 0
    for old, new in zip(rom.volumes, output.volumes):
        require(image[old.offset:old.offset+old.header_size] == result[new.offset:new.offset+new.header_size],
                'FV header changed')
        require(len(old.files) == len(new.files), 'FFS file count changed')
        for a, b in zip(old.files, new.files):
            require((a.guid, a.offset, a.extent) == (b.guid, b.offset, b.extent), 'file placement changed')
            if a.offset != file.offset:
                require(a.header+a.body == b.header+b.body, f'unselected FFS changed: {a.guid}')
            checked += 1
    extracted = [l.section.body for l in output.leaves[GUID] if l.section.kind == SECTION_PE32]
    require(extracted == [patched], 'reparsed PE differs from the expected diagnostic')
    manifest = dict(status='OFFLINE_DIAGNOSTIC_NOT_HARDWARE_TESTED', input_sha256=digest(image),
        output_sha256=digest(result), source_component_sha256=digest(source),
        result_component_sha256=digest(patched), assembly_sha256=digest((ROOT/'tools/mrc-breadcrumbs.asm').read_bytes()),
        image_base=hex(IMAGE_BASE), file_offset=hex(file.offset), component_offset=hex(offset),
        size=len(result), ffs_files_checked=checked, unselected_files_unchanged=True,
        file_positions_unchanged=True, surrounding_profiles=profiles, hunks=hunks)
    return result, patched, manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path)
    parser.add_argument('-o', '--output', type=Path, required=True)
    args = parser.parse_args()
    manifest_path = args.output.with_suffix(args.output.suffix+'.manifest.json')
    require(not args.output.exists() and not manifest_path.exists(), 'output or manifest already exists')
    result, _, manifest = build(args.input.read_bytes(), assemble())
    with args.output.open('xb') as stream:
        stream.write(result)
    with manifest_path.open('x') as stream:
        json.dump(manifest, stream, indent=2)
        stream.write('\n')
    print(f"{manifest['output_sha256']}  {args.output}")


if __name__ == '__main__':
    main()
