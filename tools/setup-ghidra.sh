#!/usr/bin/env bash
# Install a pinned Ghidra and the ghidra-firmware-utils extension for firmware analysis.
#
# Usage:
#   tools/setup-ghidra.sh [--prefix DIR] [--ghidra-zip FILE] [--gradle-home DIR]
#                         [--firmware-utils-src DIR] [--force]
#
# Example:
#   tools/setup-ghidra.sh --prefix "$HOME/.local/opt"
#
# The Ghidra and Gradle archives are checked against their published SHA-256
# before they are unpacked. The extension is built from a pinned upstream commit with a small
# compatibility patch for Ghidra 12.2. Nothing outside --prefix and the cache
# directory is written; no root access is needed.
set -euo pipefail

GHIDRA_VERSION=12.2
GHIDRA_DIRNAME=ghidra_12.2_PUBLIC
GHIDRA_URL=https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.2_build/ghidra_12.2_PUBLIC_20261016.zip
GHIDRA_SHA256=2c2cd776db3c1f6a097ba418922378ac3649cadd5e844a6f5f088ae628a7be67
GRADLE_VERSION=9.3.1
GRADLE_URL=https://services.gradle.org/distributions/gradle-9.3.1-bin.zip
GRADLE_SHA256=b266d5ff6b90eada6dc3b20cb090e3731302e553a27c5d3e4df1f0d76beaff06
FWU_REPO=https://github.com/al3xtjames/ghidra-firmware-utils.git
FWU_COMMIT=2361aa838b1aaf2575edb14d33f6bc84ec37490a
JAVA_MIN=21

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PATCH="$HERE/ghidra/ghidra-firmware-utils-12.2.patch"
PREFIX="${XDG_DATA_HOME:-$HOME/.local/share}/x99-bios-fixes"
CACHE="${XDG_CACHE_HOME:-$HOME/.cache}/x99-bios-fixes"
GHIDRA_ZIP=""
GRADLE_HOME=""
FWU_SRC=""
FORCE=0

die() { echo "setup-ghidra: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --prefix) PREFIX=$2; shift 2 ;;
    --ghidra-zip) GHIDRA_ZIP=$2; shift 2 ;;
    --gradle-home) GRADLE_HOME=$2; shift 2 ;;
    --firmware-utils-src) FWU_SRC=$2; shift 2 ;;
    --force) FORCE=1; shift ;;
    -h|--help) sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown argument: $1 (see --help)" ;;
  esac
done

check_tools() {
  local missing=()
  for tool in java javac git curl unzip sha256sum gcc; do
    command -v "$tool" >/dev/null || missing+=("$tool")
  done
  [ ${#missing[@]} -eq 0 ] || die "missing tools: ${missing[*]} (Ubuntu: apt install openjdk-21-jdk git curl unzip build-essential)"
  local version
  version=$(javac -version 2>&1 | awk '{print $2}' | cut -d. -f1)
  [ "$version" -ge "$JAVA_MIN" ] 2>/dev/null || die "JDK: expected version >= $JAVA_MIN | received ${version:-none}"
}

# download URL FILE: fetch into the cache unless already present.
download() {
  mkdir -p "$CACHE"
  [ -f "$2" ] && return
  curl -fL --retry 5 --retry-all-errors -o "$2.part" "$1" || die "download failed: $1"
  mv "$2.part" "$2"
}

# verify FILE SHA256 LABEL
verify() {
  local actual
  actual=$(sha256sum "$1" | awk '{print $1}')
  [ "$actual" = "$2" ] || die "$3 SHA-256: expected $2 | received $actual ($1)"
  echo "$3 verified."
}

fetch_ghidra() {
  if [ -z "$GHIDRA_ZIP" ]; then
    GHIDRA_ZIP="$CACHE/$(basename "$GHIDRA_URL")"
    download "$GHIDRA_URL" "$GHIDRA_ZIP"
  fi
  verify "$GHIDRA_ZIP" "$GHIDRA_SHA256" "Ghidra $GHIDRA_VERSION archive"
}

fetch_gradle() {
  if [ -n "$GRADLE_HOME" ]; then
    "$GRADLE_HOME/bin/gradle" --version 2>/dev/null | grep -q "^Gradle $GRADLE_VERSION\$" \
      || die "--gradle-home: expected Gradle $GRADLE_VERSION at $GRADLE_HOME"
    return
  fi
  GRADLE_HOME="$CACHE/gradle-$GRADLE_VERSION"
  [ -x "$GRADLE_HOME/bin/gradle" ] && return
  local zip="$CACHE/$(basename "$GRADLE_URL")"
  download "$GRADLE_URL" "$zip"
  verify "$zip" "$GRADLE_SHA256" "Gradle $GRADLE_VERSION archive"
  unzip -q "$zip" -d "$CACHE"
}

install_ghidra() {
  GHIDRA="$PREFIX/$GHIDRA_DIRNAME"
  if [ -x "$GHIDRA/support/analyzeHeadless" ]; then
    echo "Ghidra already installed at $GHIDRA."
    return
  fi
  mkdir -p "$PREFIX"
  unzip -q "$GHIDRA_ZIP" -d "$PREFIX"
  [ -x "$GHIDRA/support/analyzeHeadless" ] || die "unpacked archive: expected $GHIDRA/support/analyzeHeadless"
  echo "Ghidra installed at $GHIDRA."
}

prepare_source() {
  local src="$CACHE/ghidra-firmware-utils"
  if [ -n "$FWU_SRC" ]; then
    rm -rf "$src"
    git clone -q "$FWU_SRC" "$src"
  elif [ ! -d "$src/.git" ]; then
    git clone -q "$FWU_REPO" "$src"
  fi
  git -C "$src" fetch -q origin "$FWU_COMMIT" 2>/dev/null || true
  git -C "$src" checkout -q --force "$FWU_COMMIT" || die "ghidra-firmware-utils: commit $FWU_COMMIT not found"
  git -C "$src" clean -qfdx
  git -C "$src" apply "$PATCH" || die "patch $PATCH: does not apply to $FWU_COMMIT"
  FWU="$src"
}

build_extension() {
  GHIDRA_INSTALL_DIR="$GHIDRA" "$GRADLE_HOME/bin/gradle" -q --no-daemon -p "$FWU" buildExtension \
    || die "extension build failed (see output above)"
  EXT_ZIP=$(ls "$FWU"/dist/*ghidra-firmware-utils.zip 2>/dev/null | head -1)
  [ -n "$EXT_ZIP" ] || die "extension build: expected a zip in $FWU/dist"
}

install_extension() {
  local target="$GHIDRA/Ghidra/Extensions/ghidra-firmware-utils"
  if [ -e "$target" ] && [ "$FORCE" -ne 1 ]; then
    die "$target exists; pass --force to replace it"
  fi
  rm -rf "$target"
  unzip -q "$EXT_ZIP" -d "$GHIDRA/Ghidra/Extensions"
  [ -d "$target/data" ] || die "installed extension: expected $target/data"
  echo "Extension installed at $target."
}

check_tools
fetch_ghidra
fetch_gradle
install_ghidra
prepare_source
build_extension
install_extension
cat <<EOF

Done. Analyze extracted modules with:
  GHIDRA=$GHIDRA tools/ghidra-analyze.sh PROJECT_DIR OUTPUT_DIR module.pe [...]
EOF
