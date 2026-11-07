<#
.SYNOPSIS
    Instala y registra MalikSSM Server (malikd.exe) en un servidor Windows 24/7 con Auto-Unseal DPAPI.

.DESCRIPTION
    - Copia malikd.exe y malik.exe a $InstallDir (busca los binarios junto al script o en ..\bin).
    - Restringe $InstallDir\data a SYSTEM y Administradores.
    - Registra una tarea programada que arranca malikd como SYSTEM al iniciar Windows, sin necesidad
      de sesión iniciada. DPAPI de SYSTEM no requiere credenciales, así que el auto-unseal funciona
      tras un reinicio. Si la IP de escucha aún no existe (Tailscale arrancando), malikd sale con
      error y la tarea lo reintenta cada minuto.
    - Log del daemon en $InstallDir\data\malikd.log.
    Ejecutar en PowerShell como administrador.
#>
param(
    [int]$Port = 8443,
    [string]$InstallDir = "C:\MalikSSM",
    # 127.0.0.1 = solo este equipo. Para dar servicio a otros equipos usa la IP de Tailscale
    # (con -InsecureHttp, el túnel ya cifra) o la IP de LAN con -TlsCert/-TlsKey.
    [string]$BindAddress = "127.0.0.1",
    [string]$TlsCert = "",
    [string]$TlsKey = "",
    [switch]$InsecureHttp,
    [string]$BinDir = ""
)

$ErrorActionPreference = "Stop"

$IsLoopback = $BindAddress -in @("127.0.0.1", "localhost", "::1")
$UseTls = ($TlsCert -ne "") -and ($TlsKey -ne "")
if (-not $IsLoopback -and -not $UseTls -and -not $InsecureHttp) {
    throw "Escuchar en $BindAddress sin TLS enviaría la contraseña maestra en claro. Usa -TlsCert/-TlsKey, o -InsecureHttp solo si $BindAddress es una IP de Tailscale/WireGuard."
}

$Principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Ejecuta este script en PowerShell como administrador."
}

if ($BinDir -eq "") {
    if (Test-Path (Join-Path $PSScriptRoot "malikd.exe")) {
        $BinDir = $PSScriptRoot
    } else {
        $BinDir = Join-Path (Split-Path -Parent $PSScriptRoot) "bin"
    }
}
foreach ($exe in "malikd.exe", "malik.exe") {
    if (-not (Test-Path (Join-Path $BinDir $exe))) { throw "No se encontró $exe en $BinDir" }
}

Write-Host "=== Desplegando MalikSSM Server (malikd.exe) ===" -ForegroundColor Cyan

$TaskName = "MalikSSM-Win-Server-Daemon"
$DataDir = Join-Path $InstallDir "data"

# 0. Parar una instalación previa para poder sustituir los binarios. Si algo falla a partir de aquí,
#    se vuelve a arrancar la tarea existente para no dejar el servidor parado.
$HadTask = [bool](Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)
if ($HadTask) {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
}
$Running = Get-Process -Name malikd -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq (Join-Path $InstallDir "malikd.exe") }
$Running | Stop-Process -Force
# Stop-Process vuelve antes de que Windows libere el .exe: esperar a que termine de verdad.
$Running | Wait-Process -Timeout 15 -ErrorAction SilentlyContinue

function Copy-WithRetry([string]$From, [string]$To) {
    for ($i = 1; $i -le 10; $i++) {
        try { Copy-Item $From $To -Force -ErrorAction Stop; return }
        catch { if ($i -eq 10) { throw }; Start-Sleep -Milliseconds 500 }
    }
}

trap {
    if ($HadTask) {
        Start-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        Write-Host "✖ La instalación falló; se ha vuelto a arrancar la versión anterior ($TaskName)." -ForegroundColor Red
    }
    throw $_
}

New-Item -ItemType Directory -Path $DataDir -Force | Out-Null
Copy-WithRetry (Join-Path $BinDir "malikd.exe") (Join-Path $InstallDir "malikd.exe")
Copy-WithRetry (Join-Path $BinDir "malik.exe")  (Join-Path $InstallDir "malik.exe")
$InitVault = Join-Path $PSScriptRoot "init-vault.ps1"
if (Test-Path $InitVault) { Copy-Item $InitVault (Join-Path $InstallDir "init-vault.ps1") -Force }

# 1. data\ (bóveda, blob de auto-unseal y log) solo para SYSTEM y Administradores
icacls $DataDir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" | Out-Null
Write-Host "✔ $DataDir restringido a SYSTEM y Administradores" -ForegroundColor Green

# 2. Regla de Firewall (solo si el servidor escucha fuera de loopback), limitada a la IP de escucha
if (-not $IsLoopback) {
    $FwName = "MalikSSM-Server-TCP-$Port"
    Get-NetFirewallRule -DisplayName $FwName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    New-NetFirewallRule -DisplayName $FwName -Direction Inbound -Action Allow -Protocol TCP -LocalPort $Port -LocalAddress $BindAddress -Profile Private,Domain | Out-Null
    Write-Host "✔ Regla de Firewall para $($BindAddress):$Port" -ForegroundColor Green
}

# 3. Tarea programada: SYSTEM, al arrancar Windows, reintento cada minuto si falla
$DaemonArgs = "--addr $($BindAddress):$Port --db `"$DataDir\malik.db`""
if ($UseTls) { $DaemonArgs += " --tls-cert `"$TlsCert`" --tls-key `"$TlsKey`"" }
if ($InsecureHttp) { $DaemonArgs += " --insecure-http" }
$CmdLine = "/c `"`"$InstallDir\malikd.exe`" $DaemonArgs >> `"$DataDir\malikd.log`" 2>&1`""
$Action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument $CmdLine -WorkingDirectory $InstallDir
$Trigger = New-ScheduledTaskTrigger -AtStartup
$TaskPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -StartWhenAvailable

Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Principal $TaskPrincipal -Settings $Settings -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName

$Scheme = if ($UseTls) { "https" } else { "http" }
$LocalHost = if ($IsLoopback) { "127.0.0.1" } else { $BindAddress }
Write-Host "✔ MalikSSM Server instalado en $InstallDir y escuchando en $($BindAddress):$Port (tarea '$TaskName', SYSTEM)" -ForegroundColor Green
Write-Host "  Log: $DataDir\malikd.log" -ForegroundColor Gray
Write-Host "  Inicializa la bóveda DESDE ESTE EQUIPO (la inicialización remota se rechaza):" -ForegroundColor Yellow
Write-Host "  En sesión local:  $InstallDir\malik.exe login --server $($Scheme)://$($LocalHost):$Port --days 30" -ForegroundColor Yellow
Write-Host "  Por SSH (sin DPAPI): powershell -File $InstallDir\init-vault.ps1 -Server $($Scheme)://$($LocalHost):$Port" -ForegroundColor Yellow
