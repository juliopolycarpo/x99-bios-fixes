"""Command-line interface: scan a ROM for known defects and build patched copies.

Nothing here reads or writes a flash chip. Outputs are new files only.

Example:
    ./x99fix scan dump.bin
    ./x99fix patch dump.bin --select recommended -o dump-fixed.bin
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import hunks as H
from .records import SelectionError, load_catalog, recommended
from .rom import Rom, build, keep_extent, module_bytes, rebuilt_file, reflow, scan, walk
from .uefi import FirmwareError

LABELS = {
    "present": "DEFECT PRESENT",
    "likely-present": "likely present",
    "fixed": "fixed",
    "likely-fixed": "likely fixed",
    "partial": "PARTIAL",
    "not-detected": "not detected",
    "not-applicable": "n/a",
    "unknown-build": "unknown build",
}


def write_new(path: Path, data: bytes) -> None:
    """Create path exclusively, so an existing file is never overwritten."""
    with Path(path).open("xb") as stream:
        stream.write(data)


def load_rom(path: Path) -> Rom:
    """Parse a ROM file given on the command line."""
    return Rom(Path(path).read_bytes())


def ui_name(file) -> str:
    """Return the file's UI section name, if it has one."""
    for _, section, _ in walk(file.sections):
        if section.kind == 0x15:
            return section.body.decode("utf-16-le", "replace").rstrip("\0")
    return ""


def cmd_list(args) -> int:
    rom = load_rom(args.rom)
    for volume in rom.volumes:
        free = volume.offset + volume.length - volume.free_start
        print(f"FV {volume.offset:#09x} length {volume.length:#x} free {free:#x} files {len(volume.files)}")
        for file in volume.files:
            print(f"  {file.offset:#09x} {file.guid} type {file.kind:#04x} size {file.size:#8x} {ui_name(file)}")
    return 0


def print_scan(report, catalog) -> list[str]:
    """Print the scan table; return ids that can be patched on this exact build."""
    board = report["board"]
    print(f"Board: {board or 'unknown (signature scan only)'}")
    patchable = []
    for rid, row in report["records"].items():
        record = catalog[rid]
        tier = "hold" if record.held else f"tier {record.tier}"
        manual = record.data.get("packing") == "manual"
        if manual:
            tier = "manual"
        print(f"  {rid:<16} {LABELS[row['state']]:<15} {tier:<7} {record.data['title']}")
        if row["state"] not in ("present", "fixed", "n/a", "not-applicable"):
            print(f"  {'':<16} {row['detail']}")
        if row["state"] == "present" and not manual:
            patchable.append(rid)
    return patchable


def offer(args, rom, catalog, board, patchable) -> int:
    """Ask which patches to build into a new file; never flash anything."""
    default = [rid for rid in recommended(catalog) if rid in patchable]
    print("\nPatchable on this exact build:", " ".join(patchable) or "none")
    if not patchable:
        return 0
    answer = input(f"Build a patched copy? Enter ids, 'r' for recommended {default}, or nothing to skip: ").strip()
    if not answer:
        return 0
    ids = default if answer.lower() == "r" else answer.replace(",", " ").split()
    out = Path(input("Output file (must not exist): ").strip())
    return write_build(rom, catalog, ids, board, out, args.allow_hold)


def write_build(rom, catalog, ids, board, out: Path, allow_hold: bool) -> int:
    """Build, write the image and its manifest, and print a summary."""
    image, manifest = build(rom, catalog, ids, board, allow_hold)
    write_new(out, image)
    write_new(out.with_name(out.name + ".manifest.json"), (json.dumps(manifest, indent=2) + "\n").encode())
    print(f"Wrote {out} ({manifest['output_sha256']})")
    for note in manifest["notes"][:10]:
        print("  note:", note)
    print("Not tested on hardware. Read docs/flashing.md before writing it to a chip.")
    return 0


def cmd_scan(args) -> int:
    catalog = load_catalog()
    rom = load_rom(args.rom)
    report = scan(rom, catalog, args.board)
    if args.json:
        print(json.dumps(report, indent=2))
        return 0
    patchable = print_scan(report, catalog)
    if args.no_prompt or not sys.stdin.isatty():
        return 0
    return offer(args, rom, catalog, report["board"], patchable)


def cmd_patch(args) -> int:
    catalog = load_catalog()
    ids = [i for part in args.select for i in part.replace(",", " ").split()]
    if ids == ["recommended"]:
        ids = recommended(catalog)
    return write_build(load_rom(args.rom), catalog, ids, args.board, args.output, args.allow_hold)


def find_leaf(rom: Rom, guid: str, kind: str):
    """Return the one leaf of the given kind in the file with this GUID."""
    component = {"leaf": kind, "table_offset": 0}
    hits = [(leaf, data) for leaf in rom.leaves.get(guid.upper(), [])
            if (data := module_bytes(leaf, component)) is not None]
    if len(hits) != 1:
        raise SelectionError(f"GUID {guid}: expected one {kind} leaf | received {len(hits)}")
    return hits[0]


def cmd_extract(args) -> int:
    _, data = find_leaf(load_rom(args.rom), args.guid, args.leaf)
    write_new(args.output, data)
    print(f"Wrote {args.output}: {len(data)} bytes, sha256 {H.sha256(data)}")
    return 0


def cmd_replace(args) -> int:
    """Put a hand-edited module back into a copy of the ROM."""
    rom = load_rom(args.rom)
    leaf, old = find_leaf(rom, args.guid, args.leaf)
    new = Path(args.input).read_bytes()
    if len(new) != len(old) and not args.allow_resize:
        raise SelectionError(f"module size: expected {len(old)} | received {len(new)}; pass --allow-resize")
    body = new
    if args.leaf == "acpi-table":
        body = new + leaf.section.body[len(old):]
    data = rebuilt_file(leaf, body)
    if len(data) > leaf.file.extent and not args.allow_resize:
        raise SelectionError("rebuilt file is larger than the original slot; pass --allow-resize")
    image = bytearray(rom.image)
    data = keep_extent(data, leaf.file.extent, len(leaf.file.header))
    index = leaf.volume.files.index(leaf.file)
    if len(data) > leaf.file.extent:
        reflow(image, leaf.volume, {index: data})
    else:
        image[leaf.file.offset:leaf.file.offset + leaf.file.extent] = data + b"\xff" * (leaf.file.extent - len(data))
    _, check = find_leaf(Rom(bytes(image)), args.guid, args.leaf)
    if check != new:
        raise FirmwareError("re-parsed module differs from the input module")
    write_new(args.output, bytes(image))
    changed = sum(1 for a, b in zip(old, new) if a != b)
    print(f"Wrote {args.output}: module bytes changed {changed}, image sha256 {H.sha256(bytes(image))}")
    return 0


def cmd_derive(args) -> int:
    """Draft a board entry for another build by matching hunk signatures."""
    catalog = load_catalog()
    record = catalog[args.patch]
    component = next(c for c in record.components(args.reference) if c["name"] == args.component)
    module = Path(args.module).read_bytes()
    state, offsets = H.locate(module, component["hunks"])
    if state != H.ORIGINAL:
        raise SelectionError(f"{args.patch}/{args.component}: signatures not found uniquely in "
                             f"{args.module} | state {state}; port by hand (docs/porting.md)")
    hunks = [dict(h, offset=offset) for h, offset in zip(component["hunks"], offsets)]
    result = H.apply(module, hunks)
    draft = dict(component, hunks=hunks, source_sha256=H.sha256(module), source_size=len(module),
                 result_sha256=H.sha256(result), result_size=len(result),
                 draft="UNREVIEWED: offsets moved by signature; disassemble every hunk before use")
    print(json.dumps({"applicable": True, "components": [draft]}, indent=1))
    return 0


def parser() -> argparse.ArgumentParser:
    """Build the argument parser."""
    top = argparse.ArgumentParser(prog="x99fix", description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = top.add_subparsers(dest="command", required=True)
    p = sub.add_parser("list", help="list firmware volumes and files")
    p.add_argument("rom", type=Path)
    p.set_defaults(run=cmd_list)
    p = sub.add_parser("scan", help="report known defects and offer a patched copy")
    p.add_argument("rom", type=Path)
    p.add_argument("--board", help="force a board name instead of detecting it")
    p.add_argument("--json", action="store_true")
    p.add_argument("--no-prompt", action="store_true")
    p.add_argument("--allow-hold", action="store_true")
    p.set_defaults(run=cmd_scan)
    p = sub.add_parser("patch", help="build a patched copy with selected fixes")
    p.add_argument("rom", type=Path)
    p.add_argument("--select", required=True, nargs="+", help="patch ids, or 'recommended'")
    p.add_argument("-o", "--output", required=True, type=Path)
    p.add_argument("--board")
    p.add_argument("--allow-hold", action="store_true", help="include records marked hold")
    p.set_defaults(run=cmd_patch)
    for name, helptext in (("extract", "write one module to a file"), ("replace", "put an edited module back")):
        p = sub.add_parser(name, help=helptext)
        p.add_argument("rom", type=Path)
        p.add_argument("--guid", required=True, help="FFS file GUID")
        p.add_argument("--leaf", choices=("pe32", "acpi-table"), default="pe32")
        p.add_argument("-o", "--output", required=True, type=Path)
        if name == "replace":
            p.add_argument("--input", required=True, type=Path, help="edited module")
            p.add_argument("--allow-resize", action="store_true")
        p.set_defaults(run=cmd_extract if name == "extract" else cmd_replace)
    p = sub.add_parser("derive", help="draft a patch entry for another board's module")
    p.add_argument("--patch", required=True)
    p.add_argument("--reference", required=True, help="board the record was made for, e.g. mr9a")
    p.add_argument("--component", required=True, help="component name, e.g. UncoreInitPeim")
    p.add_argument("--module", required=True, type=Path, help="module extracted from the other board")
    p.set_defaults(run=cmd_derive)
    return top


def main(argv=None) -> int:
    """Run the CLI; returns a process exit code."""
    args = parser().parse_args(argv)
    try:
        return args.run(args)
    except (SelectionError, FirmwareError, H.HunkError, OSError, KeyError, StopIteration) as error:
        print(f"x99fix: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
