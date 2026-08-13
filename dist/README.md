# Prebuilt release layout

Official release bundles place audited native binaries in these directories:

```text
macos-arm64/sealed
macos-x64/sealed
linux-arm64/sealed
linux-x64/sealed
windows-x64/sealed.exe
```

No placeholder executable is committed. `build.sh` or `build.ps1` creates only the
binary for the current host. The top-level launchers never download a missing binary.

