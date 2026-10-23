# Same-address x64 process regression

Added for iDeck-BCD on 2026-10-22. `fixed-parent.exe` and `fixed-child.exe`
are separate x86-64 images linked at `0x140000000` with relocations stripped.
The build checks both PE headers, identical symbol addresses, and different
machine code at `fixed_code_identity`.

Build in GitHub Actions with `bash tests/proc/build-fixed-image.sh`. Its optional
first argument selects the output directory; `MINGW` selects the llvm-mingw
`bin` directory. No test binaries are automatically added to the application.

Copy both executables into one directory on the device, add `fixed-parent.exe`
to the library, and enable `env.MADEIRA_FIXED_IMAGE_ISOLATION = 1` for that entry.
The switch is off by default; restart the Wine session after changing it. It
requires the matching FEX build and the default per-process alias handling.
The parent spawns the child and stays alive during 32 event-synchronized rounds.
Each process checks its own image globals, an absolute image-data pointer, and
an indirect call to different code at the same guest RIP. The parent also checks
its state after child exit. Success is exit code 0 and:

```
[fixed-image-test] PASS: 32 simultaneous same-base rounds, child exit=42
```

Repeat the launch after exit to cover address reuse. With the switch disabled,
the existing shared-address-space implementation should refuse the child.

A host helper check and successful PE compilation do not establish that Wine,
FEX, or 1C works on iOS. Record the device run separately; this fixture contains
no 1C files and is not a substitute for launching the installed 1C client.
# Native synchronization regression (build 590)

Both executables first exercise a critical section stored in their fixed image:
recursive entry, try-entry, and 256 updates by two threads. This reproduces the
native ntdll LL/SC access that stopped 1C on build 589. Look for the separate
`PASS: image critical section` line before the simultaneous parent/child result.
Windows validates the fixture; only an iOS run validates the guarded-memory path.
