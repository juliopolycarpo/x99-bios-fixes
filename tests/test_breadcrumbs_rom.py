"""Bind the sketch to real surrounding assembly when the MR9A dump is supplied."""
import importlib.util
import os
from pathlib import Path
import struct
import unittest

from x99fix.records import load_catalog
from x99fix.rom import Rom, build, rebuilt_file
from test_breadcrumbs import FakeCmosBus, NATIVE, cp

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('build_breadcrumbs', ROOT/'tools/build_breadcrumbs.py')
BUILDER = importlib.util.module_from_spec(spec)
spec.loader.exec_module(BUILDER)

if NATIVE:
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_HOOK_INSN
    from unicorn.x86_const import (UC_X86_INS_IN, UC_X86_INS_OUT, UC_X86_REG_EAX,
        UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_ESI,
        UC_X86_REG_EDI, UC_X86_REG_EBP, UC_X86_REG_ESP, UC_X86_REG_EIP)


def setter(image, checkpoint, same_socket=True, poll=False):
    """Execute the real setter and port writer; stub only its MRC CSR helpers.

    Two matching CSR reads enter the original EBX-zeroing/polling path once.
    A differing first CSR read exercises its direct epilogue. The non-BSP path
    must skip the breadcrumb hook entirely. No hardware routines execute.
    """
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    base, context, stack, returned = BUILDER.IMAGE_BASE, 0x100000, 0x201000, 0x300000
    start = base & ~4095
    uc.mem_map(start, (base-start+len(image)+4095) & ~4095)
    uc.mem_write(base, image)
    uc.mem_map(context, 0x50000)
    uc.mem_write(context+0x62D, struct.pack('<H', 0x80))
    uc.mem_write(context+0x43D05, bytes([0 if same_socket else 1]))
    uc.mem_map(0x200000, 0x10000)
    uc.mem_map(returned, 4096)
    major, minor, location = checkpoint >> 24, (checkpoint >> 16) & 255, checkpoint & 65535
    uc.mem_write(stack, struct.pack('<IIIII', returned, context, major, minor, location))
    saved = {UC_X86_REG_EBX: 0xDEADBEEF, UC_X86_REG_ESI: 0x12345678,
             UC_X86_REG_EDI: 0x87654321, UC_X86_REG_EBP: 0x543210FF}
    for register, value in saved.items():
        uc.reg_write(register, value)
    uc.reg_write(UC_X86_REG_ESP, stack)
    bus, calls = FakeCmosBus(), []
    reads = 0

    def helper(_uc, pc, _size, _data):
        nonlocal reads
        if pc not in (0xFFE0A091, 0xFFE21388, 0xFFE21344, 0xFFE0FCF7):
            return
        sp = uc.reg_read(UC_X86_REG_ESP)
        calls.append((pc, bytes(uc.mem_read(sp+4, 4 if pc in (0xFFE0A091, 0xFFE0FCF7) else
                                              20 if pc == 0xFFE21388 else 12))))
        result = 0
        if pc == 0xFFE21344:
            reads += 1
            result = (checkpoint if poll and reads <= 2 else checkpoint ^ 0x10000) & 0xFFFF0000
        uc.reg_write(UC_X86_REG_EAX, result)
        uc.reg_write(UC_X86_REG_EIP, struct.unpack('<I', uc.mem_read(sp, 4))[0])
        uc.reg_write(UC_X86_REG_ESP, sp+4)

    def read(_uc, port, size, _data):
        assert size == 1
        return bus.read(port)

    def write(_uc, port, size, value, _data):
        assert size == 1
        bus.write(port, value)

    uc.hook_add(UC_HOOK_CODE, helper)
    uc.hook_add(UC_HOOK_INSN, read, None, 1, 0, UC_X86_INS_IN)
    uc.hook_add(UC_HOOK_INSN, write, None, 1, 0, UC_X86_INS_OUT)
    uc.emu_start(0xFFE0FE3C, returned, count=5000)
    assert uc.reg_read(UC_X86_REG_EIP) == returned, 'setter did not return'
    assert uc.reg_read(UC_X86_REG_ESP) == stack+4, 'setter unbalanced the caller stack'
    assert all(uc.reg_read(r) == v for r, v in saved.items()), 'caller nonvolatile register changed'
    return bytes(uc.mem_read(context, 0x50000)), calls, bus


@unittest.skipUnless(NATIVE and os.environ.get('X99FIX_ROM_MR9A'), 'needs NASM, Unicorn and the stock MR9A dump')
class BreadcrumbRomTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        stock = Rom(Path(os.environ['X99FIX_ROM_MR9A']).read_bytes())
        cls.base_rom, _ = build(stock, load_catalog(ROOT/'patches'), ['B01-B06', 'B02-B03'], 'mr9a')
        cls.code = BUILDER.assemble()
        cls.result, cls.patched, cls.manifest = BUILDER.build(cls.base_rom, cls.code)
        cls.original = next(l.section.body for l in Rom(cls.base_rom).leaves[BUILDER.GUID]
                            if l.section.kind == 0x10)

    def test_real_setter_preserves_both_epilogues_and_non_bsp_path(self):
        for value in (0, cp(0xB0), cp(0xB7, 0x31, 0x302), cp(0xAF, 0x42), cp(0xBF), cp(0xBE, 2)):
            for same_socket in (True, False):
                for poll in (True, False):
                    with self.subTest(checkpoint=hex(value), same_socket=same_socket, poll=poll):
                        old_memory, old_calls, old_bus = setter(self.original, value, same_socket, poll)
                        memory, calls, bus = setter(self.patched, value, same_socket, poll)
                        self.assertEqual((memory, calls, bus.post_codes), (old_memory, old_calls, old_bus.post_codes))
                        self.assertEqual(bus.other, [])
                        self.assertLessEqual(set(bus.ram), set(range(0xE0, 0xEA)))
                        if not same_socket:
                            self.assertEqual(bus.ram, {})

    def test_packed_component_and_unselected_files_are_preserved(self):
        self.assertEqual(self.manifest['result_component_sha256'], BUILDER.digest(self.patched))
        self.assertTrue(self.manifest['unselected_files_unchanged'])
        self.assertTrue(self.manifest['file_positions_unchanged'])
        self.assertGreater(self.manifest['ffs_files_checked'], 200)

    def test_wrong_source_and_already_patched_input_are_rejected(self):
        with self.assertRaisesRegex(ValueError, 'exact MR9A'):
            BUILDER.component(self.original[:-1]+bytes([self.original[-1] ^ 1]), self.code)
        with self.assertRaisesRegex(ValueError, 'exact MR9A'):
            BUILDER.build(self.result, self.code)
        with self.assertRaisesRegex(ValueError, 'assembled extent'):
            BUILDER.component(self.original, self.code[:-1])

    def test_changed_cmos_profile_is_rejected_even_with_valid_ffs_checksums(self):
        guid = BUILDER.PROFILES['CmosPei'][0]
        leaf = next(l for l in Rom(self.base_rom).leaves[guid] if l.section.kind == 0x10)
        payload = bytearray(leaf.section.body)
        payload[0xFFE87F59-0xFFE87A24] ^= 1  # alter the managed-range lower bound
        replacement = rebuilt_file(leaf, bytes(payload))
        f = leaf.file
        changed = self.base_rom[:f.offset]+replacement+self.base_rom[f.offset+len(replacement):]
        with self.assertRaisesRegex(ValueError, 'CmosPei: expected the reviewed'):
            BUILDER.build(changed, self.code)


if __name__ == '__main__':
    unittest.main()
