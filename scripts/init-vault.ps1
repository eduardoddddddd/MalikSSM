<#
.SYNOPSIS
    Inicializa la bóveda de MalikSSM desde el propio servidor (también por SSH).

.DESCRIPTION
    malikd solo acepta la inicialización desde la propia máquina. `malik login` hace lo mismo, pero
    además guarda la sesión con DPAPI, que no está disponible en sesiones SSH con clave pública.
    Este script solo llama a /v1/system/init: pide la contraseña maestra dos veces sin eco, no la
    muestra ni la guarda, y no imprime el token de sesión que devuelve el servidor.
#>
param(
    [Parameter(Mandatory = $true)][string]$Server
)

$ErrorActionPreference = "Stop"
$Server = $Server.TrimEnd("/")

$status = Invoke-RestMethod -Uri "$Server/v1/system/status" -Method Get
if ($status.initialized) {
    Write-Host "La bóveda de $Server ya está inicializada; no se hace nada." -ForegroundColor Yellow
    exit 0
}

function Read-Plain([string]$prompt) {
    $secure = Read-Host -Prompt $prompt -AsSecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

$p1 = Read-Plain "Nueva contraseña maestra de MalikSSM (mín. 12 caracteres)"
if ($p1.Length -lt 12) { throw "Demasiado corta: usa al menos 12 caracteres." }
$p2 = Read-Plain "Repítela"
if ($p1 -ne $p2) { throw "Las contraseñas no coinciden; no se ha inicializado nada." }

$body = @{ passphrase = $p1; client_host = $env:COMPUTERNAME } | ConvertTo-Json -Compress
$p1 = $null; $p2 = $null
$resp = Invoke-RestMethod -Uri "$Server/v1/system/init" -Method Post -ContentType "application/json; charset=utf-8" -Body ([Text.Encoding]::UTF8.GetBytes($body))
$body = $null

Write-Host "✔ Bóveda inicializada en $Server" -ForegroundColor Green
Write-Host ("  Desbloqueada: {0} | Auto-Unseal: {1} ({2})" -f $resp.vault.unlocked, $resp.vault.auto_unseal_ready, $resp.vault.hardware_backing)
Write-Host "  Guarda la contraseña maestra en un sitio seguro: si la pierdes, los secretos no se pueden recuperar." -ForegroundColor Yellow
