#!/usr/bin/env bash
# ==============================================================================
# MalikSSM — Instalador Automático de Cliente y Agentes para macOS y Linux
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN_DIR="$REPO_ROOT/bin"

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$ARCH" in
  x86_64|amd64) ARCH="amd64" ;;
  arm64|aarch64) ARCH="arm64" ;;
  *)
    echo "✖ Arquitectura no soportada automáticamente: $ARCH"
    exit 1
    ;;
esac

SOURCE_BIN="$BIN_DIR/malik-${OS}-${ARCH}"
if [[ ! -f "$SOURCE_BIN" ]]; then
  echo "✖ No se encontró el binario precompilado: $SOURCE_BIN"
  exit 1
fi

# 1. Instalar binario en ~/.local/bin/malik (y /usr/local/bin/malik si es escribible)
INSTALL_DIR="$HOME/.local/bin"
mkdir -p "$INSTALL_DIR"
TARGET_BIN="$INSTALL_DIR/malik"
cp "$SOURCE_BIN" "$TARGET_BIN"
chmod +x "$TARGET_BIN"

if [[ -w "/usr/local/bin" ]]; then
  cp "$SOURCE_BIN" "/usr/local/bin/malik"
  chmod +x "/usr/local/bin/malik"
  TARGET_BIN="/usr/local/bin/malik"
fi

echo "✔ Binario nativo instalado en: $TARGET_BIN ($OS/$ARCH)"

# 2. Asegurar que ~/.local/bin está en el PATH del shell
for RC in "$HOME/.zshrc" "$HOME/.bashrc"; do
  if [[ -f "$RC" ]] && ! grep -q ".local/bin" "$RC"; then
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$RC"
    echo "✔ Añadido ~/.local/bin al PATH en $RC"
  fi
done

# 3. Ejecutar init-agents para instalar la regla global en ~/.claude/CLAUDE.md
"$TARGET_BIN" init-agents

# 4. Registrar MCP en Claude Desktop (macOS y Linux)
if [[ "$OS" == "darwin" ]]; then
  CLAUDE_CFG="$HOME/Library/Application Support/Claude/claude_desktop_config.json"
else
  CLAUDE_CFG="$HOME/.config/Claude/claude_desktop_config.json"
fi

mkdir -p "$(dirname "$CLAUDE_CFG")"

if command -v python3 >/dev/null 2>&1; then
  python3 - "$CLAUDE_CFG" "$TARGET_BIN" <<'PY'
import json, os, sys
cfg_path, bin_path = sys.argv[1], sys.argv[2]
data = {}
if os.path.exists(cfg_path):
    try:
        with open(cfg_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        data = {}
if not isinstance(data.get("mcpServers"), dict):
    data["mcpServers"] = {}
data["mcpServers"]["malik"] = {
    "command": bin_path,
    "args": ["mcp", "--caller", "claude-desktop"]
}
with open(cfg_path, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)
PY
  echo "✔ Servidor MCP 'malik' registrado en: $CLAUDE_CFG"
fi

echo ""
echo "🚀 Listo. Para autenticar este equipo contra tu servidor MalikSSM ejecuta:"
echo "   malik login --server http://IP-DEL-SERVIDOR:8443 --days 30"
