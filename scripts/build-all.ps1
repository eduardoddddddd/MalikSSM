<#
.SYNOPSIS
    Compila estáticamente MalikSSM (CGO_ENABLED=0) para Windows, macOS (Apple Silicon & Intel) y Linux (x64 & ARM64).
#>
$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
Push-Location $RepoRoot

try {
    New-Item -ItemType Directory -Path "bin" -Force | Out-Null
    $env:CGO_ENABLED = "0"

    $targets = @(
        @{ GOOS = "windows"; GOARCH = "amd64"; Out = "bin\malik.exe";              Pkg = ".\cmd\malik"  },
        @{ GOOS = "windows"; GOARCH = "amd64"; Out = "bin\malikd.exe";             Pkg = ".\cmd\malikd" },
        @{ GOOS = "darwin";  GOARCH = "arm64"; Out = "bin\malik-darwin-arm64";     Pkg = ".\cmd\malik"  },
        @{ GOOS = "darwin";  GOARCH = "amd64"; Out = "bin\malik-darwin-amd64";     Pkg = ".\cmd\malik"  },
        @{ GOOS = "linux";   GOARCH = "amd64"; Out = "bin\malik-linux-amd64";      Pkg = ".\cmd\malik"  },
        @{ GOOS = "linux";   GOARCH = "arm64"; Out = "bin\malik-linux-arm64";      Pkg = ".\cmd\malik"  },
        @{ GOOS = "linux";   GOARCH = "amd64"; Out = "bin\malikd-linux-amd64";     Pkg = ".\cmd\malikd" }
    )

    foreach ($t in $targets) {
        $env:GOOS = $t.GOOS
        $env:GOARCH = $t.GOARCH
        Write-Host "Compilando $($t.Out) ($($t.GOOS)/$($t.GOARCH))..." -ForegroundColor Cyan
        go build -buildvcs=false -ldflags="-s -w" -o $t.Out $t.Pkg
    }

    $env:GOOS = "windows"
    $env:GOARCH = "amd64"
    Write-Host "`n✔ Todos los binarios multiplataforma compilados en bin/:" -ForegroundColor Green
    Get-ChildItem bin\* | Select-Object Name, @{Name="MB";Expression={[math]::Round($_.Length / 1MB, 2)}} | Format-Table -AutoSize
} finally {
    Pop-Location
}
