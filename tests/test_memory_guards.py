"""MRC safety regressions; emulation and real ROM checks are optional dependencies."""
import importlib.util
import copy
import json
import os
from pathlib import Path
import shutil
import struct
import unittest

from x99fix import hunks as H
from x99fix.rom import Rom, module_bytes

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('memory_guard_builder', ROOT/'tools/rebuild_memory_guards.py')
BUILDER = importlib.util.module_from_spec(spec)
spec.loader.exec_module(BUILDER)
try:
    import pefile
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE
    from unicorn.x86_const import (UC_X86_REG_EIP, UC_X86_REG_ESP, UC_X86_REG_EBP,
        UC_X86_REG_EAX, UC_X86_REG_ECX, UC_X86_REG_EDX)
    NATIVE = True
except ImportError:
    NATIVE = False

CASES = [
    (1, 0, 0, True), (2, 1, 0, True), (4, 2, 0, True), (8, 3, 0, True),
    (3, 0, 0, False), (1, 0, 1, False), (1, 0, 255, False), (0, 0, 0, False),
    (16, 4, 0, False), (1, 32, 0, False), (0x80000001, 0, 0, False), (2, 0, 0, False),
]


def execute(image, image_base, entry, resume, halt, active, bsp, history):
    """Stop at the old gate or original terminal halt; no hardware routine executes."""
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    start = image_base & ~4095
    uc.mem_map(start, ((image_base-start+len(image)+4095)//4096)*4096)
    uc.mem_write(image_base, image)
    for destination in {resume & ~4095, halt & ~4095}:
        if not any(begin <= destination <= end for begin, end, _ in uc.mem_regions()):
            uc.mem_map(destination, 4096)
    stack, context = 0x201000, 0x300000
    uc.mem_map(0x200000, 0x10000)
    uc.mem_map(context, 0x70000)
    uc.mem_write(stack, struct.pack('<II', 0xdeadbeef, context))
    uc.mem_write(context+0x220fc, struct.pack('<I', active))
    uc.mem_write(context+0x43d05, bytes([bsp]))
    uc.mem_write(context+0x22108, bytes([history]))
    uc.reg_write(UC_X86_REG_ESP, stack)
    saved = {UC_X86_REG_EAX: 0x12345678, UC_X86_REG_ECX: 0xabcdef01, UC_X86_REG_EDX: 0x98765432}
    for reg, value in saved.items():
        uc.reg_write(reg, value)
    visited = []

    def hook(_uc, pc, _size, _data):
        if pc in (resume, halt):
            visited.append(pc)
            uc.emu_stop()
    uc.hook_add(UC_HOOK_CODE, hook)
    uc.emu_start(entry, 0xffffffff, count=100)
    if visited == [resume]:
        # Original prologue established exactly this frame; volatile inputs are preserved.
        assert uc.reg_read(UC_X86_REG_EBP) == stack-4
        assert uc.reg_read(UC_X86_REG_ESP) == stack-28
        assert all(uc.reg_read(reg) == value for reg, value in saved.items())
    return visited


@unittest.skipUnless(NATIVE and shutil.which('nasm'), 'requires unicorn, pefile and nasm')
class GuardSourceTests(unittest.TestCase):
    def test_only_sole_bsp_without_initialized_workers_resumes(self):
        guard, resume, halt = 0x100000, 0x900100, 0x900000
        image = BUILDER.assemble(guard, resume, halt)
        for active, bsp, history, allowed in CASES:
            with self.subTest(active=active, bsp=bsp, history=history):
                self.assertEqual(execute(image, guard, guard, resume, halt, active, bsp, history),
                                 [resume if allowed else halt])


@unittest.skipUnless(os.environ.get('X99FIX_ROM_PR9') or os.environ.get('X99FIX_ROM_MR9A'),
                     'set X99FIX_ROM_PR9 / X99FIX_ROM_MR9A for exact component tests')
class GuardRecordTests(unittest.TestCase):
    def components(self):
        for board in ('pr9', 'mr9a'):
            path = os.environ.get('X99FIX_ROM_'+board.upper())
            if not path:
                continue
            rom = Rom(Path(path).read_bytes())
            for rid in ('B07-B08', 'B01-B04-B06-B08'):
                record = json.loads((ROOT/'patches'/(rid+'.json')).read_text())
                c = record['boards'][board]['components'][0]
                original = next(data for leaf in rom.leaves[c['ffs_guid']]
                    if (data := module_bytes(leaf, c)) is not None and H.sha256(data) == c['source_sha256'])
                yield board, record, c, original

    def test_exact_application_reversal_and_idempotent_recipe(self):
        for board, record, c, original in self.components():
            with self.subTest(board=board, patch=record['id']):
                candidate = H.apply(original, c['hunks'])
                self.assertEqual(H.sha256(candidate), c['result_sha256'])
                self.assertEqual(len(candidate), c['result_size'])
                self.assertEqual(H.apply(candidate, c['hunks'], reverse=True), original)
                if shutil.which('nasm'):
                    self.assertEqual(BUILDER.update(record, board, original), record)
                    tampered = copy.deepcopy(record)
                    altered = tampered['boards'][board]['components'][0]
                    tail = altered['hunks'][-1]
                    changed = bytes.fromhex(tail['after'])
                    tail['after'] = (changed[:-1] + bytes([changed[-1] ^ 1])).hex()
                    altered['result_sha256'] = H.sha256(H.apply(original, altered['hunks']))
                    with self.assertRaisesRegex(ValueError, 'guarded record differs'):
                        BUILDER.update(tampered, board, original)

    @unittest.skipUnless(NATIVE, 'requires unicorn and pefile')
    def test_exported_bytes_at_original_and_relocated_bases(self):
        for board, record, c, original in self.components():
            candidate = H.apply(original, c['hunks'])
            old, new = pefile.PE(data=original), pefile.PE(data=candidate)
            meta = c['memory_failure_guard']
            self.assertEqual([d.__pack__() for d in old.OPTIONAL_HEADER.DATA_DIRECTORY],
                             [d.__pack__() for d in new.OPTIONAL_HEADER.DATA_DIRECTORY])
            self.assertEqual(new.OPTIONAL_HEADER.SizeOfImage, len(candidate))
            self.assertEqual(new.OPTIONAL_HEADER.SizeOfCode, sum(s.SizeOfRawData for s in new.sections if s.Characteristics & 0x20))
            self.assertEqual(new.OPTIONAL_HEADER.SizeOfInitializedData, sum(s.SizeOfRawData for s in new.sections if s.Characteristics & 0x40))
            self.assertEqual(new.sections[-1].Characteristics, 0x60000060)
            for base in (old.OPTIONAL_HEADER.ImageBase, 0x10000000):
                mapped = pefile.PE(data=candidate)
                mapped.relocate_image(base)
                entry = base + meta['entry_offset']
                halt = meta['halt_fn'] - old.OPTIONAL_HEADER.ImageBase + base
                for active, bsp, history, allowed in CASES:
                    with self.subTest(board=board, patch=record['id'], base=base, active=active, bsp=bsp, history=history):
                        self.assertEqual(execute(mapped.get_memory_mapped_image(), base, entry, entry+6, halt,
                                                 active, bsp, history), [entry+6 if allowed else halt])
