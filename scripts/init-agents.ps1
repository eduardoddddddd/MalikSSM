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

# 2. Ejecutar malik init-agents (escribe regla en ~/.claude/CLAUDE.md)
& $MalikExe init-agents

# 3. Registrar MCP en Claude Desktop (%APPDATA%\Claude\claude_desktop_config.json)
$ClaudeConfigPath = Join-Path $env:APPDATA "Claude\claude_desktop_config.json"
$ClaudeDir = Split-Path -Parent $ClaudeConfigPath
if (-not (Test-Path $ClaudeDir)) {
    New-Item -ItemType Directory -Path $ClaudeDir -Force | Out-Null
}
$ClaudeJson = @{ mcpServers = @{} }
if (Test-Path $ClaudeConfigPath) {
    try {
        $Parsed = Get-Content $ClaudeConfigPath -Raw | ConvertFrom-Json -AsHashtable
        if ($Parsed) { $ClaudeJson = $Parsed }
    } catch {}
}
if (-not $ClaudeJson.ContainsKey("mcpServers") -or $null -eq $ClaudeJson["mcpServers"]) {
    $ClaudeJson["mcpServers"] = @{}
}
$ClaudeJson["mcpServers"]["malik"] = @{
    command = $MalikExe
    args    = @("mcp", "--caller", "claude-desktop")
}
$ClaudeJson | ConvertTo-Json -Depth 10 | Set-Content $ClaudeConfigPath -Encoding UTF8
Write-Host "✔ Servidor MCP 'malik' registrado en Claude Desktop: $ClaudeConfigPath" -ForegroundColor Green

Write-Host "`nListo. Ahora solo tienes que hacer 'malik login' por la mañana y todos tus agentes hablarán con la ROG Ally." -ForegroundColor Cyan
