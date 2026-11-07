<#
.SYNOPSIS
    Configura malik.exe en cualquiera de tus ordenadores:
    - Añade malik.exe al PATH de tu usuario de Windows
    - Registra el servidor MCP nativo (malik.exe mcp) en Claude Desktop y Antigravity (sin tokens expuestos)
    - Instala la regla global "Zero-Nagging" para que ningún agente vuelva a pedirte contraseñas por chat
#>
$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
$BinDir = Join-Path $RepoRoot "bin"
$MalikExe = Join-Path $BinDir "malik.exe"

if (-not (Test-Path $MalikExe)) {
    throw "No se encontró $MalikExe. Compílalo primero con 'go build -o bin/malik.exe ./cmd/malik'."
}

# 1. Añadir al PATH de usuario si no está
$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($UserPath -notlike "*$BinDir*") {
    [Environment]::SetEnvironmentVariable("Path", "$UserPath;$BinDir", "User")
    $env:Path = "$env:Path;$BinDir"
    Write-Host "✔ Añadido $BinDir al PATH de tu usuario de Windows" -ForegroundColor Green
}

# 2. malik init-agents: regla en ~/.claude/CLAUDE.md y registro del MCP en Claude Desktop.
#    El merge del JSON lo hace el binario (conserva los demás MCP, crea copia previa y aborta si
#    el fichero no se puede leer), así no depende de la versión de PowerShell.
& $MalikExe init-agents
if ($LASTEXITCODE -ne 0) {
    throw "malik init-agents falló (código $LASTEXITCODE); claude_desktop_config.json no se ha modificado."
}

Write-Host "`nListo. Ahora solo tienes que hacer 'malik login' por la mañana y todos tus agentes hablarán con la Servidor Central." -ForegroundColor Cyan
