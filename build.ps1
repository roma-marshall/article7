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
if (-not $IsWindows) {
    throw "build.ps1 currently supports Windows only"
}

$Architecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
if ($Architecture -ne [System.Runtime.InteropServices.Architecture]::X64) {
    throw "Only Windows x86_64 is an official v1 target"
}

cargo fmt -- --check
cargo check --offline --locked
cargo test --offline --locked
cargo build --release --offline --locked

$OutputDir = Join-Path $ProjectDir "dist/windows-x64"
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
$Output = Join-Path $OutputDir "sealed.exe"
Copy-Item -Force "target/release/sealed.exe" $Output
Write-Output "Built $Output"

