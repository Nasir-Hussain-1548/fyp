#!/usr/bin/env bash
set -euo pipefail
# Build a single self-extracting Windows installer (percepta-agent-setup.exe)
# Contents: percepta-agent-gui.exe, percepta-agent-core.exe, install.ps1
# Requires: 7z and 7zS.sfx (usually from p7zip-full on Linux)

ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)
OUT_DIR="$ROOT_DIR/server/agent_builds"
TARGET_DIR_MSVS="$ROOT_DIR/target/x86_64-pc-windows-msvc/release"
TARGET_DIR_GNU="$ROOT_DIR/target/x86_64-pc-windows-gnu/release"

mkdir -p "$OUT_DIR"
cd "$OUT_DIR"

# Verify tools
if ! command -v 7z >/dev/null 2>&1; then
  echo "Error: 7z not found. Install p7zip/7zip." >&2
  exit 1
fi

# Find sfx stub
SFX_STUB="/usr/lib/p7zip/7zS.sfx"
if [[ ! -f "$SFX_STUB" ]]; then
  # Fallback common locations
  for p in /usr/lib/p7zip/7zS2.sfx /usr/lib/7zip/7z.sfx /usr/lib/7zip/7zS.sfx; do
    if [[ -f "$p" ]]; then SFX_STUB="$p"; break; fi
  done
fi
if [[ ! -f "$SFX_STUB" ]]; then
  echo "Error: 7z SFX stub not found (7zS.sfx)." >&2
  exit 1
fi

# Locate binaries from agent builds or cargo targets
GUI_CANDIDATES=(
  "$OUT_DIR/percepta-agent-gui.exe"
  "$TARGET_DIR_MSVS/gui.exe"
  "$TARGET_DIR_GNU/gui.exe"
)
CORE_CANDIDATES=(
  "$OUT_DIR/percepta-agent-core.exe"
  "$TARGET_DIR_MSVS/percepta-agent.exe"
  "$TARGET_DIR_GNU/percepta-agent.exe"
)

GUI_SRC=""
for f in "${GUI_CANDIDATES[@]}"; do
  [[ -f "$f" ]] && GUI_SRC="$f" && break
done
if [[ -z "$GUI_SRC" ]]; then
  echo "Error: GUI binary not found. Expected one of: ${GUI_CANDIDATES[*]}" >&2
  exit 1
fi

CORE_SRC=""
for f in "${CORE_CANDIDATES[@]}"; do
  [[ -f "$f" ]] && CORE_SRC="$f" && break
done
if [[ -z "$CORE_SRC" ]]; then
  echo "Error: Core binary not found. Expected one of: ${CORE_CANDIDATES[*]}" >&2
  exit 1
fi

# Normalize names inside installer payload
cp -f "$GUI_SRC" "$OUT_DIR/percepta-agent-gui.exe"
# If core came from target as percepta-agent.exe, rename for consistency
cp -f "$CORE_SRC" "$OUT_DIR/percepta-agent-core.exe"

# Create a bootstrap installer that launches the GUI. GUI handles CA/OTK fetch and service install.
cat > "$OUT_DIR/install.ps1" <<'PS1'
$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$GuiExe = Join-Path $ScriptDir "percepta-agent-gui.exe"

Write-Host "[+] Launching Percepta Agent GUI installer..." -ForegroundColor Green
Start-Process -FilePath $GuiExe -Verb RunAs
PS1

# Create SFX config to run the bootstrap
cat > "$OUT_DIR/installer_sfx.txt" <<'CFG'
;!@Install@!UTF-8!
RunProgram="powershell.exe -ExecutionPolicy Bypass -File install.ps1"
GUIMode="2"
;!@InstallEnd@!
CFG

# Build 7z payload
rm -f payload.7z percepta-agent-setup.exe || true
7z a -t7z -mx9 payload.7z \
  percepta-agent-gui.exe \
  percepta-agent-core.exe \
  install.ps1 > /dev/null

# Assemble self-extracting EXE
cat "$SFX_STUB" installer_sfx.txt payload.7z > percepta-agent-setup.exe
chmod +x percepta-agent-setup.exe

echo "Created $OUT_DIR/percepta-agent-setup.exe"
