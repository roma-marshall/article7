$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$ProjectDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ProjectDir

if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    throw "Cargo is required for a source build"
}
if (-not (Test-Path Cargo.lock) -or -not (Test-Path .cargo/config.toml) -or -not (Test-Path vendor)) {
    throw "Locked vendored dependency state is incomplete"
}
if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
    throw "build.ps1 currently supports Windows only"
}

if ($env:PROCESSOR_ARCHITECTURE -ne "AMD64") {
    throw "Only Windows x86_64 is an official v1 target"
}

cargo fmt -- --check
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
cargo check --offline --locked
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
cargo test --offline --locked
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
cargo build --release --offline --locked
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$OutputDir = Join-Path $ProjectDir "dist/windows-x64"
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
$Output = Join-Path $OutputDir "sealed.exe"
Copy-Item -Force "target/release/sealed.exe" $Output
Write-Output "Built $Output"
