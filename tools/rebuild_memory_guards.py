#!/usr/bin/env python3
"""Reproduce the four guarded MRC records from exact stock dumps (requires NASM).

Example: python3 tools/rebuild_memory_guards.py --pr9 stock-pr9.bin --mr9a stock-mr9a.bin
Reads ROM files, never hardware. Existing records must match pinned pre-guard
identities or contain this exact reversible guard revision. Writes JSON only.
"""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from x99fix import hunks as H
from x99fix.pe import branch_fields, sections
from x99fix.rom import Rom, module_bytes

PREFIX = bytes.fromhex('5589e583ec18')
# Exact legacy candidates and entry offsets; never infer patch sites by a loose signature.
PROFILES = {
    ('B07-B08', 'pr9'): ('cb0d28573c5905ed10d928d0fe96aba23ad3a46e3dafc3f491b14a240acdab0d', 608064, 607607, 0xffdf29f0),
    ('B07-B08', 'mr9a'): ('fee9ab71350ee999005a0b2460bae59025aefe9cb9bdc1d052cc3400d8faca0c', 606976, 606519, 0xffe093bf),
    ('B01-B04-B06-B08', 'pr9'): ('d642c8f9f477775ff2936cd6af08cdcb19eb569afc60dab04545a1a7ce2cfba9', 608992, 608582, 0xffdf29f0),
    ('B01-B04-B06-B08', 'mr9a'): ('1f07e6dfea11aba1533fb6e6f83dfcc24c686d8a5530c569ecc2580a303cff40', 607904, 607494, 0xffe093bf),
}


def assemble(guard_va, resume_va, halt_fn):
    """Assemble the reviewed source without writing build products in the repo."""
    with tempfile.TemporaryDirectory() as temporary:
        output = Path(temporary) / 'guard.bin'
        subprocess.run(['nasm', '-f', 'bin', f'-DGUARD_VA={guard_va}',
            f'-DRESUME_VA={resume_va}', f'-DHALT_FN={halt_fn}', '-o', str(output),
            str(ROOT / 'tools/memory-failure-guard.asm')], check=True)
        return output.read_bytes()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def pe_fields(data):
    """Locate the PE32 aggregate sizes and final executable-section size fields."""
    header = struct.unpack_from('<I', data, 0x3c)[0]
    optional = header + 24
    require(data[header:header+4] == b'PE\0\0' and struct.unpack_from('<H', data, optional)[0] == 0x10b, 'expected PE32')
    count, opt_size = struct.unpack_from('<H', data, header+6)[0], struct.unpack_from('<H', data, header+20)[0]
    last = optional + opt_size + (count-1)*40
    require(struct.unpack_from('<II', data, optional+32) == (32, 32), 'unexpected PE alignment')
    require(struct.unpack_from('<I', data, last+36)[0] == 0x60000060, 'final section must be retained executable code/data')
    for rva, _, raw, size in sections(data):
        require(rva == raw, 'candidate must have identical raw offsets and RVAs')
    require(raw + size == len(data), 'final section must end at EOF')
    return optional, [optional+4, optional+8, optional+56, last+8, last+16]


def guarded(legacy, entry, halt):
    """Add a sole-active-BSP/no-initialized-workers gate before the old gate."""
    optional, fields = pe_fields(legacy)
    image_base = struct.unpack_from('<I', legacy, optional+28)[0]
    require(legacy[entry:entry+6] == PREFIX, 'displaced prologue differs')
    code = assemble(image_base+len(legacy), image_base+entry+6, halt)
    extent = (len(code)+31) & ~31
    result = bytearray(legacy + code + bytes(extent-len(code)))
    result[entry:entry+6] = b'\xe9' + struct.pack('<i', len(legacy)-entry-5) + b'\x90'
    old_headers = []
    for offset in fields:
        old = struct.unpack_from('<I', legacy, offset)[0]
        # VirtualSize includes only the live helper; RawSize includes alignment.
        # The old candidate already has padding, which now precedes the guard.
        is_virtual_size = offset == fields[-2]
        value = (len(legacy) - sections(legacy)[-1][2] + len(code)) if is_virtual_size else old+extent
        struct.pack_into('<I', result, offset, value)
        old_headers.append(dict(offset=offset, value=old))
    meta = dict(revision=1, legacy_sha256=H.sha256(legacy), legacy_size=len(legacy),
        entry_offset=entry, displaced_prologue=PREFIX.hex(), guard_offset=len(legacy),
        guard_size=len(code), halt_fn=halt, legacy_headers=old_headers,
        assembly_sha256=H.sha256((ROOT/'tools/memory-failure-guard.asm').read_bytes()))
    return bytes(result), meta


def updated_hunks(original, result, template, findings, meta):
    """Preserve the reviewed hunk boundaries, signatures and finding provenance."""
    hunks, covered = copy.deepcopy(template), set()
    for h in hunks:
        offset, before, after = H.decoded(h)
        covered.update(range(offset, offset+len(before)))
        h['after'] = (result[offset:offset+len(before)] if before else result[offset:]).hex()
        if not before:
            lead = len(bytes.fromhex(h.get('context_before', '')))
            jump = meta['entry_offset'] - offset + lead
            code = result[meta['guard_offset']:meta['guard_offset']+meta['guard_size']]
            masks = set(h.get('wild_after', [])) | set(range(jump+1, jump+5))
            masks.update(lead+meta['guard_offset']-offset+i for i in branch_fields(code))
            h['wild_after'] = sorted(masks)
    # Include any newly changed header bytes outside the original hunk ranges.
    start = None
    for at in range(len(original)+1):
        changed = at < len(original) and at not in covered and original[at] != result[at]
        if changed and start is None:
            start = at
        elif not changed and start is not None:
            hunks.append(dict(offset=start, before=original[start:at].hex(), after=result[start:at].hex(),
                context_before=original[max(0,start-16):start].hex(), context_after=original[at:at+16].hex(),
                findings=findings, wild_before=[], wild_after=[]))
            start = None
    hunks.sort(key=lambda h: h['offset'])
    require(H.apply(original, hunks) == result, 'exported hunks do not reproduce guarded bytes')
    return hunks


def update(record, board, original):
    """Regenerate a component idempotently; reject unrecognized starting bytes."""
    result = copy.deepcopy(record)
    comp = result['boards'][board]['components'][0]
    expected_hash, size, entry, halt = PROFILES[(record['id'], board)]
    require(H.sha256(original) == comp['source_sha256'], 'wrong source component')
    candidate = H.apply(original, comp['hunks'])
    require(H.sha256(candidate) == comp['result_sha256'], 'existing result hash differs')
    legacy = candidate
    if 'memory_failure_guard' in comp:
        meta = comp['memory_failure_guard']
        require(meta['revision'] == 1 and meta['legacy_size'] == size and meta['entry_offset'] == entry, 'unknown guard revision')
        legacy = bytearray(candidate[:size])
        legacy[entry:entry+6] = PREFIX
        for row in meta['legacy_headers']:
            struct.pack_into('<I', legacy, row['offset'], row['value'])
        legacy = bytes(legacy)
    require(len(legacy) == size and H.sha256(legacy) == expected_hash, 'unrecognized legacy component')
    fixed, meta = guarded(legacy, entry, halt)
    if 'memory_failure_guard' in comp:
        require(fixed == candidate and meta == comp['memory_failure_guard'], 'guarded record differs from source recipe')
    comp.update(result_sha256=H.sha256(fixed), result_size=len(fixed),
        hunks=updated_hunks(original, fixed, comp['hunks'], record['findings'], meta), memory_failure_guard=meta)
    note = ' Failure/reset continuation requires a sole active BSP and no prior initialized remote workers; uncertain worker state takes the existing terminal halt before callbacks.'
    if note not in result['limits']:
        result['limits'] += note
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pr9', type=Path, required=True)
    parser.add_argument('--mr9a', type=Path, required=True)
    args = parser.parse_args()
    roms = {board: Rom(getattr(args, board).read_bytes()) for board in ('pr9', 'mr9a')}
    prepared = []
    for rid in sorted({key[0] for key in PROFILES}):
        path = ROOT / 'patches' / (rid+'.json')
        record = json.loads(path.read_text())
        for board in ('pr9', 'mr9a'):
            comp = record['boards'][board]['components'][0]
            matches = [data for leaf in roms[board].leaves.get(comp['ffs_guid'], [])
                       if (data := module_bytes(leaf, comp)) is not None and H.sha256(data) == comp['source_sha256']]
            require(len(matches) == 1, f'{board}: expected one exact original UncoreInitPeim')
            record = update(record, board, matches[0])
        prepared.append((path, json.dumps(record, indent=1)+'\n'))
    for path, text in prepared:
        path.write_text(text)
        print(path.relative_to(ROOT))


if __name__ == '__main__':
    main()
