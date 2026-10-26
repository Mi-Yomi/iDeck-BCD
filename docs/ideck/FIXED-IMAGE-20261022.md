# iDeck-BCD: process-private fixed x64 images

Fork-local change, 2026-10-22. Opt-in: `env.MADEIRA_FIXED_IMAGE_ISOLATION = 1`.
Set it on the launcher entry before starting a fresh Wine session. It requires
the matching rebuilt `xtajit64.dll` and default per-process alias callbacks.

## Problem and behavior

Wine's iOS port runs Windows processes in one host address space. Two x64
executables without relocations, such as the reported `1cestart.exe` and
`1cv8s.exe`, can require the same image base while both processes remain alive.
Moving the PE header or waiting for the parent to exit cannot solve that case.

With the switch enabled, each eligible fixed x64 image has private backing.
The original guest range is reserved with no access from the first process
onward, so an untranslated child access cannot silently read its parent.
Windows still sees the original image base in the PE header, loader, query and
server records. Owner-aware Wine paths and FEX translate image access to the
current process's backing. Pure x64 images do not consume native executable
pool copies; FEX compiles their code into its existing private emulator cache.

The FEX callback uses an explicit versioned tag and checked data export, distinct
from ARM64EC execution aliases. Decode, scalar/atomic data accesses, protection,
self-modification and unmap notifications follow the appropriate address domain.
Unmap withdraws the window and process teardown releases its backing. Guest
guards remain reserved for the session. Wine's native I/O boundary translates
image buffers before kernel copyin/copyout; cross-process memory operations use
the target process owner.

The feature is limited to non-hybrid, non-builtin, non-resource AMD64 images
with stripped relocations and a preferred base at or above 4 GiB. It does not
implement a separate address space for arbitrary heaps or every Windows mapping.
The switch defaults to off. Existing relocatable images follow the existing path.
Unknown native fault encodings and unaligned native atomics are refused rather
than emulated with non-atomic copies. Build 590 handles bounded native LL/SC
sequences (load, optional register-only ALU/comparison, optional mismatch branch
to CLREX, store) as a hardware CAS on the current owner's backing. Native retry
branches, status registers and NZCV are preserved; other exclusive sequences
still fail closed. A device log can reveal whether an application needs one of
these additional native paths; the supported FEX atomics translate before access.
Native pins and the shipped PE ntdll ABI are unchanged; FEX changes are applied
by a checked fork-local build overlay and restored after the build.

## Validation

Actions runs compiled host tests for the actual native window registry, guard
reservation and I/O helper, plus extracted production FEX callback/address IR.
It rebuilds FEX, verifies `IosGuestWindowAbi` in the resulting DLL, and builds
two distinct executables at the identical fixed address. A separate
`fixed-image-test-<build>` artifact includes these executables and their instructions
in `FIXED-IMAGE.md`; the two IPAs remain in `unsigned-ipa-<build>`.

See `tests/proc/FIXED-IMAGE.md` for the simultaneous parent/child device test.
Build 589 device evidence: the fixed-image switch was active and the guard was
reserved, but `1cestart.exe` faulted on `LDAXR W9,[X8]` (`885ffd09`) inside native
ntdll critical-section entry, accessing image data at `0x14005fa00`. No child
launcher execution was reached. This is a confirmed gap in 589, not an installer
or configuration failure. Build 590 adds the bounded LL/SC path and a device
fixture using a global critical section, recursive entry and competing threads.
Build 590 device evidence: native LL/SC service succeeds and `1cestart.exe`
starts `1cv8s.exe`. Its `frame.dll` then fails with `c0000135` because
`oledlg.dll` is missing. Error cleanup faults in `core83.dll`, then repeatedly
calls into unmapped modules. Later process retirement stops in
`ios_fex_fixed_window_abi` while holding the virtual-memory lock; the Mach
exception thread waits for that lock and the desktop stops responding.

Build 591 adds Wine's `oledlg.dll` to the existing extra-DLL build and requires
its exports and regular imports in the packaging gate. The fixed-image ABI
probe now skips retired mappings and uses bounded, fault-safe Mach reads for
all PE metadata. Process retirement drops the owning emulator callback before
unmapping its fixed image. Host regressions cover inaccessible PE pages, every
failed read, malformed export bounds and callback removal before unmapping.

Build 591 device evidence: `frame.dll` and `oledlg.dll` load and the desktop
stays responsive. `1cv8s.exe` then loads `backbas.dll`, which fails with
`c0000135` because `odbc32.dll` is missing; `core83.dll` reads a null pointer
and the process ends with `c0000005`. Repeated launches of the shortcut then
ran several 1C clients at once and exhausted the 576 MB JIT pool, so later
clients could not map `frame.dll` or `WebKit.dll` (`c0000017`).

Build 592 adds Wine's `odbc32.dll` the same way and requires it in the
packaging gate. Its DllMain succeeds without the unix-side library, so only
Windows ODBC drivers are available.

Build 608 device evidence (BCD 0.1.600 merged; iPhone17,2, iOS 27, the Wine
desktop): `1cestart.exe` and `1cv8s.exe` run and the "Запуск 1С:Предприятия"
window opens. Adding an infobase starts `1cv8.exe CREATEINFOBASE`, which first
failed to map `WebKit.dll`, `CFLite.dll` and then `frame.dll` itself
(`c0000017`): the session's JIT pool had shrunk to 560 MB and every pure x64
DLL of each 1C process was copied into it (1C's "Ошибка загрузки компоненты
frame: 126" and ": 8"). With `env.MADEIRA_X64_IMAGE_NOCOPY = 1` and
`pool-split = 1` in the desktop's own file the pool is 885 MB, no image is
copied and the first `CREATEINFOBASE` in a fresh session wrote the file
infobase and exited with 0. The launcher then read a NULL pointer in
`core83.dll`, so the base never reached its list; in the same session a second
launcher and a second `CREATEINFOBASE` threw during `frame.dll`'s start-up
(after the first 91 modules, before `richui.dll`), showed a message box and
ended with 1. The message's text was not readable: `[win-name]` printed
non-ASCII characters as `?` until build 609.

Build 609 device test: **NOT RUN**. The separate fixed-image device fixture has
not been run on iOS either. The repository contains no 1C binaries or business
databases.

For 1C, start the Wine desktop with these lines in its own file, then start
`1cestart.exe` once from a fresh session:

    env.MADEIRA_FIXED_IMAGE_ISOLATION = 1
    env.MADEIRA_X64_IMAGE_NOCOPY = 1
    pool-split = 1
    env.MADEIRA_TLS_CLEAR_OWN_PROCESS = 1

The last line is why the launcher crashed after a written infobase (build 608
log, 2026-10-26): at its exit `1cv8.exe`'s TlsFree cleared cells 9, 12, 13,
20, 24, 30 and 31 in the launcher's live threads as well (`[tls-cross-clear]`:
every process of a session shares one thread list), and `1cv8s.exe` then read
its context through core83's `TlsGetValue` (core83.dll 8.3.18.1208, RVA 0x646d0,
called from `core::URL` at 0x22a406) as NULL. With the line a TlsFree clears
the calling process's threads only, as on Windows.

A useful device log contains `[fixed-image] reserved guest ...; backing is
private per process`, `[pool-split] JIT pool = ...` and, from build 609, the
text of every 1C message box in its `[win-name]` lines.
