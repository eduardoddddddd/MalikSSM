<#
.SYNOPSIS
    Instala y registra MalikSSM Server (malikd.exe) en la Windows Server para ejecución 24/7 con Auto-Unseal DPAPI/TPM.
#>
param(
    [int]$Port = 8443,
    [string]$InstallDir = "C:\MalikSSM",
    # 127.0.0.1 = solo este equipo. Para dar servicio a otros equipos usa la IP de Tailscale
    # (con -InsecureHttp, el túnel ya cifra) o la IP de LAN con -TlsCert/-TlsKey.
    [string]$BindAddress = "127.0.0.1",
    [string]$TlsCert = "",
    [string]$TlsKey = "",
    [switch]$InsecureHttp
)

$IsLoopback = $BindAddress -in @("127.0.0.1", "localhost", "::1")
$UseTls = ($TlsCert -ne "") -and ($TlsKey -ne "")
if (-not $IsLoopback -and -not $UseTls -and -not $InsecureHttp) {
    throw "Escuchar en $BindAddress sin TLS enviaría la contraseña maestra en claro. Usa -TlsCert/-TlsKey, o -InsecureHttp solo si $BindAddress es una IP de Tailscale/WireGuard."
}

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
$BinDir = Join-Path $RepoRoot "bin"

Write-Host "=== Desplegando MalikSSM Server (malikd.exe) para Windows Server ===" -ForegroundColor Cyan

if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}
if (-not (Test-Path "$InstallDir\data")) {
    New-Item -ItemType Directory -Path "$InstallDir\data" -Force | Out-Null
}

Copy-Item "$BinDir\malikd.exe" "$InstallDir\malikd.exe" -Force
Copy-Item "$BinDir\malik.exe"  "$InstallDir\malik.exe"  -Force

# 1. Regla de Firewall (solo si el servidor escucha fuera de loopback), limitada a la IP de escucha
if (-not $IsLoopback) {
    $FwName = "MalikSSM-Server-TCP-$Port"
    if (-not (Get-NetFirewallRule -DisplayName $FwName -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName $FwName -Direction Inbound -Action Allow -Protocol TCP -LocalPort $Port -LocalAddress $BindAddress -Profile Private,Domain -ErrorAction SilentlyContinue | Out-Null
        Write-Host "✔ Regla de Firewall creada para $($BindAddress):$Port" -ForegroundColor Green
    }
}

# 2. Tarea Programada de arranque automático en Windows (compatible con DPAPI de tu usuario en la Servidor Central)
$TaskName = "MalikSSM-Win-Server-Daemon"
$DaemonArgs = "--addr $($BindAddress):$Port --db `"$InstallDir\data\malik.db`""
if ($UseTls) { $DaemonArgs += " --tls-cert `"$TlsCert`" --tls-key `"$TlsKey`"" }
if ($InsecureHttp) { $DaemonArgs += " --insecure-http" }
$Action = New-ScheduledTaskAction -Execute "$InstallDir\malikd.exe" -Argument $DaemonArgs -WorkingDirectory $InstallDir
$TriggerLogon = New-ScheduledTaskTrigger -AtLogOn
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)

Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $TriggerLogon -Settings $Settings -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName

$Scheme = if ($UseTls) { "https" } else { "http" }
Write-Host "✔ MalikSSM Server instalado en $InstallDir y escuchando en $($BindAddress):$Port" -ForegroundColor Green
Write-Host "  Inicializa la bóveda DESDE ESTE EQUIPO (la inicialización remota se rechaza):" -ForegroundColor Yellow
Write-Host "  $($Scheme)://127.0.0.1:$Port/ui" -ForegroundColor Yellow
