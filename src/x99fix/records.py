"""Load patch records and resolve a selection into a consistent set.

Example:
    catalog = load_catalog()
    chosen = resolve(catalog, ["B01-B06", "B02-B03"], board="mr9a")
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

PATCH_DIR = Path(os.environ.get("X99FIX_PATCHES", Path(__file__).resolve().parents[2] / "patches"))


class SelectionError(ValueError):
    """A requested patch selection cannot be combined or applied."""


@dataclass(frozen=True)
class Record:
    """One patch record: a defect batch with per-board components."""

    data: dict

    @property
    def id(self) -> str:
        return self.data["id"]

    @property
    def tier(self):
        return self.data.get("tier", 2)

    @property
    def held(self) -> bool:
        return self.tier == "hold"

    def board(self, name: str) -> dict:
        """Return the board entry, or a not-applicable placeholder."""
        return self.data["boards"].get(name, {"applicable": False, "reason": "No record for this board."})

    def components(self, board: str) -> list[dict]:
        """Return component entries for one board; empty when not applicable."""
        entry = self.board(board)
        return entry.get("components", []) if entry.get("applicable") else []


def load_catalog(directory: Path = PATCH_DIR) -> dict[str, Record]:
    """Read every *.json record in directory, keyed by record id."""
    catalog = {}
    for path in sorted(Path(directory).glob("*.json")):
        data = json.loads(path.read_text())
        if data.get("schema") != 1:
            raise SelectionError(f"{path.name}: expected schema 1 | received {data.get('schema')!r}")
        catalog[data["id"]] = Record(data)
    if not catalog:
        raise SelectionError(f"patch directory {directory}: expected *.json records | received none")
    return catalog


def boards(catalog: dict[str, Record]) -> list[str]:
    """Return every board name any record mentions."""
    return sorted({name for record in catalog.values() for name in record.data["boards"]})


def recommended(catalog: dict[str, Record]) -> list[str]:
    """Return the tier-1 record ids, the suggested first patches."""
    return sorted(rid for rid, record in catalog.items() if record.tier == 1)


def included(catalog: dict[str, Record], ids) -> set[str]:
    """Return selected records and every correction they transitively include."""
    result, pending = set(), list(ids)
    while pending:
        rid = pending.pop()
        if rid not in result:
            result.add(rid)
            pending.extend(catalog[rid].data.get("supersedes", []))
    return result


def minimal(catalog: dict[str, Record], ids) -> list[str]:
    """Keep one application unit per correction, preserving selection order."""
    chosen = list(dict.fromkeys(ids))
    covered = set()
    for rid in chosen:
        older = included(catalog, catalog[rid].data.get("supersedes", []))
        if rid in older:
            raise SelectionError(f"{rid}: circular supersedes relationship")
        covered.update(older)
    return [rid for rid in chosen if rid not in covered]


def resolve(catalog: dict[str, Record], ids: list[str], board: str,
            allow_hold: bool = False) -> tuple[list[Record], list[str]]:
    """Validate a selection; return (records, notes).

    Superseded records are dropped in favour of the record that contains
    them. Conflicting records, held records (unless allow_hold) and records
    that do not apply to the board raise SelectionError.
    """
    notes, unknown = [], [rid for rid in ids if rid not in catalog]
    if unknown:
        raise SelectionError(f"patch ids {unknown}: expected one of {sorted(catalog)}")
    chosen = minimal(catalog, ids)
    for older in dict.fromkeys(ids):
        if older not in chosen:
            owner = next(rid for rid in chosen if older in included(catalog, [rid]))
            notes.append(f"{older} dropped: {owner} already contains it")
    for rid in chosen:
        record = catalog[rid]
        clash = [other for other in record.data.get("conflicts", []) if other in chosen]
        if clash:
            raise SelectionError(f"{rid} conflicts with {clash}: they edit the same bytes; choose one")
        if record.held and not allow_hold:
            raise SelectionError(f"{rid} is on hold ({record.data['limits'][:80]}...); pass --allow-hold to include it")
        if not record.board(board).get("applicable"):
            raise SelectionError(f"{rid} does not apply to {board}: {record.board(board).get('reason')}")
    return [catalog[rid] for rid in chosen], notes
