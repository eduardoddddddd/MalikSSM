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

# 3. malik init-agents: regla global en ~/.claude/CLAUDE.md y registro del MCP en Claude Desktop.
#    El binario conserva los demás servidores MCP, crea copia previa y aborta si el JSON no se puede leer.
"$TARGET_BIN" init-agents

echo ""
echo "🚀 Listo. Para autenticar este equipo contra tu servidor MalikSSM ejecuta:"
echo "   malik login --server http://IP-TAILSCALE-DEL-SERVIDOR:8443 --days 30   (https:// si el servidor usa TLS)"
