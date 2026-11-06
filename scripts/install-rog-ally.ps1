<#
.SYNOPSIS
    Instala y registra MalikSSM Server (malikd.exe) en la ASUS ROG Ally para ejecución 24/7 con Auto-Unseal DPAPI/TPM.
#>
param(
    [int]$Port = 8443,
    [string]$InstallDir = "C:\MalikSSM"
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
$BinDir = Join-Path $RepoRoot "bin"

Write-Host "=== Desplegando MalikSSM Server (malikd.exe) para ASUS ROG Ally ===" -ForegroundColor Cyan

if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}
if (-not (Test-Path "$InstallDir\data")) {
    New-Item -ItemType Directory -Path "$InstallDir\data" -Force | Out-Null
}

Copy-Item "$BinDir\malikd.exe" "$InstallDir\malikd.exe" -Force
Copy-Item "$BinDir\malik.exe"  "$InstallDir\malik.exe"  -Force

# 1. Regla de Firewall para permitir conexiones desde tus ordenadores (LAN y Tailscale)
$FwName = "MalikSSM-Server-TCP-$Port"
if (-not (Get-NetFirewallRule -DisplayName $FwName -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -DisplayName $FwName -Direction Inbound -Action Allow -Protocol TCP -LocalPort $Port -Profile Private,Domain -ErrorAction SilentlyContinue | Out-Null
    Write-Host "✔ Regla de Firewall creada para el puerto TCP $Port" -ForegroundColor Green
}

# 2. Tarea Programada de arranque automático en Windows (compatible con DPAPI de tu usuario en la ROG Ally)
$TaskName = "MalikSSM-ROG-Ally-Daemon"
$Action = New-ScheduledTaskAction -Execute "$InstallDir\malikd.exe" -Argument "--addr 0.0.0.0:$Port --db `"$InstallDir\data\malik.db`"" -WorkingDirectory $InstallDir
$TriggerLogon = New-ScheduledTaskTrigger -AtLogOn
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)

Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $TriggerLogon -Settings $Settings -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName

Write-Host "✔ MalikSSM Server instalado en $InstallDir y ejecutándose en el puerto $Port" -ForegroundColor Green
Write-Host "  Panel Web: http://127.0.0.1:$Port/ui" -ForegroundColor Yellow
