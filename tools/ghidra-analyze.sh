#!/usr/bin/env bash
# Import firmware modules into a Ghidra project and export C, assembly and JSON.
#
# Usage:
#   GHIDRA=/path/to/ghidra_12.2_PUBLIC tools/ghidra-analyze.sh PROJECT_DIR OUTPUT_DIR module.pe [...]
#
# Example:
#   ./x99fix extract dump.bin --guid D71C8BA4-4AF2-4D0D-B1BA-F2409F0C20D3 -o UncoreInitPeim.pe
#   tools/ghidra-analyze.sh work/project work/exports UncoreInitPeim.pe
#
# Output per module: NAME.c (approximate decompilation), NAME.asm (instructions
# with exact bytes) and NAME.json (functions, calls and ranges).
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
GHIDRA="${GHIDRA:-${XDG_DATA_HOME:-$HOME/.local/share}/x99-bios-fixes/ghidra_12.2_PUBLIC}"
HEADLESS="$GHIDRA/support/analyzeHeadless"
DATA="$GHIDRA/Ghidra/Extensions/ghidra-firmware-utils/data"

[ $# -ge 3 ] || { sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }
[ -x "$HEADLESS" ] || { echo "ghidra-analyze: expected $HEADLESS; run tools/setup-ghidra.sh or set GHIDRA" >&2; exit 1; }
[ -d "$DATA" ] || { echo "ghidra-analyze: expected extension data at $DATA; run tools/setup-ghidra.sh" >&2; exit 1; }

PROJECT=$1 OUTPUT=$2
shift 2
mkdir -p "$PROJECT" "$OUTPUT"
exec "$HEADLESS" "$PROJECT" x99 -import "$@" -overwrite \
  -scriptPath "$HERE/ghidra" \
  -preScript SetupFirmwareMemory.java \
  -postScript PeimUEFIHelper.java "$DATA" \
  -postScript ExportFirmware.java "$OUTPUT" \
  -analysisTimeoutPerFile 600
