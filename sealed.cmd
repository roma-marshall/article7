@echo off
setlocal
set "PROJECT_DIR=%~dp0"

if /I not "%PROCESSOR_ARCHITECTURE%"=="AMD64" (
  echo sealed: only Windows x86_64 is supported by this release 1>&2
  exit /b 1
)

set "BINARY=%PROJECT_DIR%dist\windows-x64\sealed.exe"
if not exist "%BINARY%" (
  echo sealed: bundled binary is missing: %BINARY% 1>&2
  echo Build from vendored source with .\build.ps1 or obtain a verified release bundle. 1>&2
  exit /b 1
)
"%BINARY%" %*
exit /b %ERRORLEVEL%

