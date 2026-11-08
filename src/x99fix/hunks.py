"""Apply, reverse and inspect byte hunks with per-hunk guards.

A hunk is {"offset", "before", "after"} in hex, with offset in the coordinates
of the original component. Hunks from several patches can be applied to one
component as long as their ranges do not overlap; each hunk checks its own
original bytes, so the order of independent patches does not matter.

Example:
    fixed = apply(original, [{"offset": 4, "before": "00", "after": "01"}])
"""

from __future__ import annotations

import hashlib
import re

ORIGINAL, FIXED, MIXED, MISMATCH = "original", "fixed", "mixed", "mismatch"


class HunkError(ValueError):
    """Hunk bytes or ranges do not match the component."""


def sha256(data: bytes) -> str:
    """Return a hex SHA-256 digest; e.g. sha256(b'')[:8] == 'e3b0c442'."""
    return hashlib.sha256(data).hexdigest()


def decoded(hunk: dict) -> tuple[int, bytes, bytes]:
    """Return (offset, before, after) as bytes for one hunk record."""
    return hunk["offset"], bytes.fromhex(hunk["before"]), bytes.fromhex(hunk["after"])


def ordered(hunks: list[dict]) -> list[tuple[int, bytes, bytes]]:
    """Sort hunks by offset and reject overlapping original ranges."""
    rows = sorted((decoded(h) for h in hunks), key=lambda row: row[0])
    end, last_insert = -1, None
    for offset, before, _ in rows:
        if offset < end or (not before and offset == last_insert):
            raise HunkError(f"hunk at {offset:#x}: overlaps the previous hunk ending at {end:#x}")
        end = offset + len(before)
        last_insert = offset if not before else None
    return rows


def apply(data: bytes, hunks: list[dict], reverse: bool = False) -> bytes:
    """Splice every hunk into data after checking its guard bytes.

    Offsets are in original coordinates for forward application. For reverse
    application, data must be the fully patched result of the same hunk list.
    """
    rows = ordered(hunks)
    out, cursor, shift = bytearray(), 0, 0
    for offset, before, after in rows:
        old, new = (after, before) if reverse else (before, after)
        at = offset + shift if reverse else offset
        if data[at:at + len(old)] != old:
            raise HunkError(f"hunk at {offset:#x}: expected {old[:16].hex()} | received "
                            f"{data[at:at + len(old)][:16].hex()}")
        out += data[cursor:at] + new
        cursor = at + len(old)
        if reverse:
            shift += len(after) - len(before)
    out += data[cursor:]
    return bytes(out)


def state(data: bytes, hunks: list[dict], shift_map: list[tuple[int, int]] | None = None) -> str:
    """Report whether every hunk shows its original or fixed bytes.

    shift_map lists (offset, delta) for size changes of other patches that sit
    before these hunks; independent same-size patches need none.
    """
    seen = set()
    for offset, before, after in ordered(hunks):
        at = offset + sum(delta for start, delta in (shift_map or []) if start < offset)
        if before and data[at:at + len(before)] == before:
            seen.add(ORIGINAL)
        elif after and data[at:at + len(after)] == after:
            seen.add(FIXED)
        elif not before and len(data) == at:
            seen.add(ORIGINAL)
        else:
            return MISMATCH
    if len(seen) == 1:
        return seen.pop()
    return MIXED


def find_unique(data: bytes, pattern: bytes, wild: list[int] | None = None) -> int | None:
    """Return the only offset of pattern in data, or None when absent or repeated.

    Positions listed in wild match any byte.
    """
    if not wild:
        first = data.find(pattern)
        if first < 0 or data.find(pattern, first + 1) >= 0:
            return None
        return first
    masked = set(wild)
    regex = b"".join(b"." if i in masked else re.escape(pattern[i:i + 1]) for i in range(len(pattern)))
    hits = [m.start() for m in re.finditer(b"(?=" + regex + b")", data, re.DOTALL)]
    return hits[0] if len(hits) == 1 else None


def signature(hunk: dict, fixed: bool = False) -> tuple[bytes, int, list[int]]:
    """Return (pattern, hunk start within it, wildcard positions) from stored context."""
    _, before, after = decoded(hunk)
    lead = bytes.fromhex(hunk.get("context_before", ""))
    tail = bytes.fromhex(hunk.get("context_after", ""))
    wild = hunk.get("wild_after" if fixed else "wild_before", [])
    return lead + (after if fixed else before) + tail, len(lead), wild


def locate(data: bytes, hunks: list[dict]) -> tuple[str, list[int | None]]:
    """Find hunks in a module of a different build by unique context signature.

    Returns (state, offsets): ORIGINAL when every original-bytes signature is
    found exactly once, FIXED when every fixed signature is, otherwise
    MISMATCH. Offsets are positions of each hunk in data. Appended hunks
    (empty before) are skipped, since their position is the module end.
    """
    for wanted, fixed in ((ORIGINAL, False), (FIXED, True)):
        offsets = []
        for hunk in hunks:
            if not hunk["before"]:
                offsets.append(len(data))
                continue
            pattern, lead, wild = signature(hunk, fixed)
            found = find_unique(data, pattern, wild)
            offsets.append(None if found is None else found + lead)
        if all(item is not None for item in offsets):
            return wanted, offsets
    return MISMATCH, []
