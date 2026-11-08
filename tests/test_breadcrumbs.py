"""MRC breadcrumb sketch: emulate the assembled hook, and decode its CMOS bytes.

Emulation needs NASM and Unicorn and is skipped without them. The hook calls
only its own regions, so no vendor bytes are needed.
"""
import importlib.util
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('read_breadcrumbs', ROOT/'tools/read_breadcrumbs.py')
READER = importlib.util.module_from_spec(spec)
spec.loader.exec_module(READER)
try:
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_INSN
    from unicorn.x86_const import (UC_X86_INS_IN, UC_X86_INS_OUT, UC_X86_REG_EBP,
        UC_X86_REG_EDI, UC_X86_REG_ESI, UC_X86_REG_ESP)
    NATIVE = shutil.which('nasm') is not None
except ImportError:
    NATIVE = False

# region, linked address, size: the order NASM emits them
REGIONS = [('r0', 0xFFE4276C, 30), ('ra', 0xFFE613A2, 88), ('rb', 0xFFE61903, 53),
           ('site', 0xFFE0FEA9, 5)]
HOOK = 0xFFE613A2
CTX, STACK_TOP, RETURN = 0x00100000, 0x00200000, 0x00300000
STATE, SLOT0, SLOT1, COUNT = 0xE0, 0xE1, 0xE5, 0xE9


def cp(major, minor=0, location=0):
    return (major << 24) | (minor << 16) | location


GOOD = [cp(0xB0), cp(0xB0, 2), cp(0xB1), cp(0xB6), cp(0xB7, 0, 0x0101), cp(0xB7, 0x2A, 0x0203),
        cp(0xBD), cp(0xB9), cp(0xBA), cp(0xBF), cp(0xBE, 2)]
RESET = [cp(0xB0), cp(0xB1), cp(0xAF, 0x42)]
STUCK_B7 = [cp(0xB0), cp(0xB1), cp(0xB6), cp(0xB7, 0x31, 0x0302)]
STUCK_B0 = [cp(0xB0), cp(0xB0, 2, 0x0001)]


def assemble():
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp)/'breadcrumbs.bin'
        subprocess.run(['nasm', '-f', 'bin', '-o', str(out), str(ROOT/'tools/mrc-breadcrumbs.asm')], check=True)
        return out.read_bytes()


class FakeCmosBus:
    """Upper-bank CMOS on ports 72h/73h plus a port-80 log. Unset bytes read FFh."""

    def __init__(self, upper=None):
        self.ram, self.index, self.post_codes, self.other = dict(upper or {}), None, [], []

    def read(self, port):
        if port != 0x73:
            raise AssertionError(f'(in): expected port 0x73 | received {port:#x}')
        return self.ram.get(self.index, 0xFF)

    def write(self, port, value):
        if port == 0x72:
            self.index = value
        elif port == 0x73:
            self.ram[self.index] = value
        elif port == 0x80:
            self.post_codes.append(value)
        else:
            self.other.append((port, value))

    def slot(self, base):
        return struct.unpack('<I', bytes(self.ram.get(base+i, 0xFF) for i in range(4)))[0]

    def snapshot(self):
        return {i: self.ram.get(i, 0xFF) for i in READER.LAYOUT}


class Machine:
    """Runs the hook the way the patched call site enters it: esi = ctx, edi = checkpoint."""

    def __init__(self, code, bus):
        self.bus, self.uc = bus, Uc(UC_ARCH_X86, UC_MODE_32)
        self.uc.mem_map(0xFFE0F000, 0x53000)
        cursor = 0
        for _, va, size in REGIONS:
            self.uc.mem_write(va, code[cursor:cursor+size])
            cursor += size
        self.uc.mem_map(CTX, 0x1000)
        self.uc.mem_write(CTX+0x62D, struct.pack('<H', 0x80))
        self.uc.mem_map(STACK_TOP-0x10000, 0x10000)
        self.uc.mem_map(RETURN, 0x1000)
        self.uc.mem_write(RETURN, b'\xf4')
        self.uc.hook_add(UC_HOOK_INSN, lambda uc, port, size, user: bus.read(port), None, 1, 0, UC_X86_INS_IN)
        self.uc.hook_add(UC_HOOK_INSN, lambda uc, port, size, value, user: bus.write(port, value & 0xFF),
                         None, 1, 0, UC_X86_INS_OUT)

    def boot(self, checkpoints):
        for value in checkpoints:
            esp = STACK_TOP-0x100
            self.uc.mem_write(esp, struct.pack('<I', RETURN))
            for reg, val in ((UC_X86_REG_ESP, esp), (UC_X86_REG_ESI, CTX), (UC_X86_REG_EBP, 0x1234),
                             (UC_X86_REG_EDI, value)):
                self.uc.reg_write(reg, val)
            self.uc.emu_start(HOOK, RETURN, count=2000)
            kept = tuple(self.uc.reg_read(r) for r in (UC_X86_REG_ESI, UC_X86_REG_EBP, UC_X86_REG_ESP))
            if kept != (CTX, 0x1234, esp+4):
                raise AssertionError(f'(esi, ebp, esp): expected {(CTX, 0x1234, esp+4)} | received {kept}')


@unittest.skipUnless(NATIVE, 'needs nasm and unicorn')
class HookTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.code = assemble()

    def run_boots(self, *boots, upper=None):
        bus = FakeCmosBus(upper)
        machine = Machine(self.code, bus)
        for boot in boots:
            machine.boot(boot)
        return bus

    def assert_byte(self, bus, index, expected):
        got = bus.ram.get(index, 0xFF)
        self.assertEqual(got, expected, f'(CMOS {index:#x}): expected {expected:#04x} | received {got:#04x}')

    def assert_slot(self, bus, base, expected):
        got = bus.slot(base)
        self.assertEqual(got, expected, f'(slot {base:#x}): expected {expected:#010x} | received {got:#010x}')

    def test_regions_fill_their_space(self):
        self.assertEqual(len(self.code), sum(size for _, _, size in REGIONS))

    def test_call_site_targets_hook(self):
        site = self.code[-5:]
        target = 0xFFE0FEA9 + 5 + struct.unpack('<i', site[1:])[0]
        self.assertEqual((site[0], target), (0xE8, HOOK), f'(call site): expected call {HOOK:#x} | received {site.hex()}')

    def test_port80_receives_every_major(self):
        bus = self.run_boots(GOOD)
        self.assertEqual(bus.post_codes, [v >> 24 for v in GOOD])
        self.assertEqual(bus.other, [])

    def test_first_boot_after_clear_arms_and_stops_at_bf(self):
        bus = self.run_boots(GOOD)
        self.assert_byte(bus, STATE, 0xA1)
        self.assert_byte(bus, COUNT, 0)
        self.assert_slot(bus, SLOT0, cp(0xBF))

    def test_stuck_b7_is_kept_for_next_good_boot(self):
        bus = self.run_boots(GOOD, STUCK_B7, GOOD)
        self.assert_byte(bus, STATE, 0xA3)
        self.assert_byte(bus, COUNT, 1)
        self.assert_slot(bus, SLOT0, cp(0xB7, 0x31, 0x0302))
        self.assert_slot(bus, SLOT1, cp(0xBF))

    def test_stuck_b0_keeps_minor_and_location(self):
        bus = self.run_boots(GOOD, STUCK_B0, GOOD)
        self.assert_slot(bus, SLOT0, cp(0xB0, 2, 0x0001))

    def test_mrc_reset_pass_is_not_a_failure(self):
        bus = self.run_boots(GOOD, RESET, GOOD)
        self.assert_byte(bus, COUNT, 0)

    def test_failure_survives_following_reset_pass(self):
        bus = self.run_boots(GOOD, STUCK_B7, RESET, GOOD)
        self.assert_byte(bus, COUNT, 1)
        self.assert_slot(bus, SLOT0, cp(0xB7, 0x31, 0x0302))

    def test_second_failure_replaces_first(self):
        bus = self.run_boots(GOOD, STUCK_B7, STUCK_B0, GOOD)
        self.assert_byte(bus, COUNT, 2)
        self.assert_slot(bus, SLOT1, cp(0xB0, 2, 0x0001))

    def test_count_saturates(self):
        bus = self.run_boots(GOOD, upper={STATE: 0xA0, COUNT: 0xFF})
        self.assert_byte(bus, COUNT, 0xFF)

    def test_garbage_state_rearms_with_zero_count(self):
        bus = self.run_boots(STUCK_B7, upper={STATE: 0x5C, COUNT: 0x77})
        self.assert_byte(bus, COUNT, 0)
        self.assert_byte(bus, STATE, 0xA0)

    def test_writes_stay_inside_layout(self):
        bus = self.run_boots(GOOD, STUCK_B7, RESET, GOOD)
        self.assertLessEqual(set(bus.ram), set(READER.LAYOUT), f'(written): {sorted(map(hex, bus.ram))}')

    def test_reader_decodes_emulated_failure(self):
        info = READER.decode(self.run_boots(GOOD, STUCK_B7, GOOD).snapshot())
        self.assertEqual(info['last_failure'], {'major': 0xB7, 'minor': 0x31, 'location': 0x0302})
        self.assertEqual((info['failures'], info['active']['major']), (1, 0xBF))


class ReaderTests(unittest.TestCase):
    def test_cleared_cmos_is_not_armed(self):
        info = READER.decode({i: 0xFF for i in READER.LAYOUT})
        self.assertFalse(info['armed'], f'(armed): expected False | received {info}')

    def test_inactive_slot_hidden_without_failures(self):
        raw = {i: 0 for i in READER.LAYOUT} | {STATE: 0xA1, SLOT0+3: 0xBF}
        info = READER.decode(raw)
        self.assertIsNone(info['last_failure'], f'(last_failure): expected None | received {info}')
        self.assertEqual(READER.describe(info['active']), 'BF/00 location 0000')

    def test_missing_index_is_named(self):
        with self.assertRaisesRegex(ValueError, r"missing \['0xe9'\]"):
            READER.decode({i: 0 for i in READER.LAYOUT if i != 0xE9})


if __name__ == '__main__':
    unittest.main()
