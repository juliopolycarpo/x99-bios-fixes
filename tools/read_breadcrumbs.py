#!/usr/bin/env python3
"""Read the MRC breadcrumbs from upper-bank CMOS on Linux (read-only).

Example: sudo python3 tools/read_breadcrumbs.py
Reads indexes E0-E9 through ports 72h/73h only. It never touches port 70h
(that index register also holds the NMI mask) and never writes CMOS data.
See docs/boot-breadcrumbs.md for the layout.
"""
from __future__ import annotations

import os
import struct
import sys

STATE, SLOT0, COUNT = 0xE0, 0xE1, 0xE9
LAYOUT = range(0xE0, 0xEA)


class DevPort:
    """Upper-bank CMOS reader over /dev/port.

    Example: DevPort().read(0xE0)
    """

    def __init__(self, path: str = '/dev/port'):
        self.fd = os.open(path, os.O_RDWR)

    def read(self, index: int) -> int:
        os.lseek(self.fd, 0x72, os.SEEK_SET)
        os.write(self.fd, bytes([index]))
        os.lseek(self.fd, 0x73, os.SEEK_SET)
        return os.read(self.fd, 1)[0]


def decode(raw: dict[int, int]) -> dict:
    """Decode bytes E0-E9 into the active record and the last failed pass.

    Example: decode({i: DevPort().read(i) for i in LAYOUT})['last_failure']
    """
    missing = [hex(i) for i in LAYOUT if i not in raw]
    if missing:
        raise ValueError(f'(raw): expected indexes E0-E9 | missing {missing}')
    state = raw[STATE]
    if state & 0xFC != 0xA0:
        return {'armed': False, 'state': state}
    slot = (state >> 1) & 1

    def record(n: int) -> dict:
        value = struct.unpack('<I', bytes(raw[SLOT0 + 4 * n + i] for i in range(4)))[0]
        return {'major': value >> 24, 'minor': (value >> 16) & 0xFF, 'location': value & 0xFFFF}

    count = raw[COUNT]
    return {
        'armed': True,
        'state': state,
        'pass_ended': bool(state & 1),
        'active': record(slot),
        'failures': count,
        'last_failure': record(slot ^ 1) if count else None,
    }


def describe(rec: dict) -> str:
    """Format a record as major/minor and location.

    Example: describe({'major': 0xB7, 'minor': 0x31, 'location': 0x302}) == 'B7/31 location 0302'
    """
    return f"{rec['major']:02X}/{rec['minor']:02X} location {rec['location']:04X}"


def main() -> int:
    port = DevPort()
    info = decode({i: port.read(i) for i in LAYOUT})
    if not info['armed']:
        print(f"not armed (state {info['state']:#04x}): patched firmware not booted yet, or CMOS cleared")
        return 1
    print(f"stored MRC pass: {describe(info['active'])}, pass ended: {info['pass_ended']}")
    saturated = ' (saturated)' if info['failures'] == 0xFF else ''
    print(f"failed MRC passes since arming: {info['failures']}{saturated}")
    if info['last_failure']:
        print(f"last failed pass stopped at: {describe(info['last_failure'])}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
