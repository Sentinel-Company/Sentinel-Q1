# Hybrid Titan - Build Script
# Requires: Rust (rustup), C++ (MSVC or MinGW), CMake

param(
    [switch]$CheckOnly
)

$ErrorActionPreference = "Stop"

function Test-Command($cmd) {
    try {
        Get-Command $cmd -ErrorAction Stop | Out-Null
        return $true
    } catch {
        return $false
    }
}

Write-Host "=== Hybrid Titan - Dependency Check ===" -ForegroundColor Cyan

# 1. Rust
if (-not (Test-Command "cargo")) {
    Write-Host "[HATA] Rust/Cargo bulunamadi!" -ForegroundColor Red
    Write-Host "  Kurulum: https://rustup.rs" -ForegroundColor Yellow
    Write-Host "  veya: winget install Rustlang.Rustup" -ForegroundColor Yellow
    Write-Host ""
    if (-not $CheckOnly) { exit 1 }
} else {
    $rustVer = cargo --version
    Write-Host "[OK] Rust: $rustVer" -ForegroundColor Green
}

# 2. CMake
if (-not (Test-Command "cmake")) {
    Write-Host "[HATA] CMake bulunamadi!" -ForegroundColor Red
    Write-Host "  Kurulum: winget install Kitware.CMake" -ForegroundColor Yellow
    Write-Host ""
    if (-not $CheckOnly) { exit 1 }
} else {
    $cmakeVer = cmake --version 2>$null | Select-Object -First 1
    Write-Host "[OK] CMake: $cmakeVer" -ForegroundColor Green
}

# 3. C++ Compiler (cl or g++)
$hasCxx = (Test-Command "cl") -or (Test-Command "g++")
if (-not $hasCxx) {
    Write-Host "[UYARI] C++ derleyici bulunamadi (cl veya g++)" -ForegroundColor Yellow
    Write-Host "  MSVC: Visual Studio Build Tools yukleyin" -ForegroundColor Yellow
    Write-Host "  MinGW: winget install mingw" -ForegroundColor Yellow
} else {
    Write-Host "[OK] C++ derleyici mevcut" -ForegroundColor Green
}

if ($CheckOnly) {
    Write-Host ""
    Write-Host "Kontrol tamamlandi. Eksik varsa yukaridaki talimatlari takip edin." -ForegroundColor Cyan
    exit 0
}

Write-Host ""
Write-Host "=== Building Rust Core ===" -ForegroundColor Cyan
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $projectRoot

# MSVC target (varsayilan) - Visual Studio ortami gerekli
# VS yoksa: "x64 Native Tools Command Prompt for VS" acip oradan calistirin
if (-not (Test-Command "cl")) {
    Write-Host "MSVC ortami yukleniyor..." -ForegroundColor Yellow
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vswhere) {
        $vsPath = & $vswhere -latest -property installationPath 2>$null
        if ($vsPath) {
            $vcvars = Join-Path $vsPath "VC\Auxiliary\Build\vcvars64.bat"
            if (Test-Path $vcvars) {
                cmd /c "`"$vcvars`" && set" | ForEach-Object {
                    if ($_ -match "^([^=]+)=(.*)$") { [Environment]::SetEnvironmentVariable($matches[1], $matches[2], "Process") }
                }
            }
        }
    }
}

cargo build --release
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

if /
Write-Host ""
Write-Host "=== Building C++ Strategy Engine ===" -ForegroundColor Cyan
$buildDir = Join-Path $projectRoot "build"
if (-not (Test-Path $buildDir)) { New-Item -ItemType Directory -Path $buildDir | Out-Null }
Set-Location $buildDir

# MSVC ile derleme
$hasCl = Test-Command "cl"
if (-not $hasCl) {
    Write-Host "[HATA] MSVC (cl) bulunamadi!" -ForegroundColor Red
    Write-Host "  Visual Studio Build Tools yukleyin veya" -ForegroundColor Yellow
    Write-Host "  'x64 Native Tools Command Prompt for VS' acip oradan .\build.ps1 calistirin" -ForegroundColor Yellow
    exit 1
}
Write-Host "MSVC ile derleniyor..." -ForegroundColor Gray
cmake -G "Visual Studio 17 2022" -A x64 ..\cpp 2>$null
if ($LASTEXITCODE -ne 0) { cmake -G "Visual Studio 16 2019" -A x64 ..\cpp 2>$null }
if ($LASTEXITCODE -ne 0) { cmake -G "Ninja" -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=cl -DCMAKE_CXX_COMPILER=cl ..\cpp }

cmake --build . --config Release
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host ""
Write-Host "=== Build Complete ===" -ForegroundColor Green
$exe = Get-ChildItem -Path $buildDir -Recurse -Filter "nova_hybrid.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
if ($exe) {
    Write-Host "Calistir: $($exe.FullName)" -ForegroundColor Cyan
}

hahahaha kral projeye 1 senedir uğraşiyorum değeri baya geçen baktiğimda 280m du 