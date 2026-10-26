#!/usr/bin/env python3
"""iDeck, 2026-10-22: execute the real FEX guest-window and alias helpers.

The two namespaces in the C++ harness represent the two private xtajit64 images
used by concurrent pseudo-processes. The test catches the original ambiguity:
the same guest image base must decode to different backing bytes, without
creating a native EC execution alias or changing guest control-flow identity.
No device/1C execution is claimed. Default needs a C++ host compiler; pass
--static-only explicitly to check overlay/ABI wiring on a host without one.
"""
from pathlib import Path
import argparse
import importlib.util
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--fex-root', type=Path, default=ROOT / 'FEX')
    parser.add_argument('--static-only', action='store_true')
    args = parser.parse_args()
    overlay = load('guest_windows', ROOT / 'tools/patch-fex-ios-guest-windows.py')
    ev = load('fex_eval', ROOT / 'tests/host/fexpatch_eval.py')
    before = {rel: (args.fex_root / rel).read_text() for rel in overlay.EDITS}
    patched = overlay.patch(before)
    assert patched != before and overlay.patch(patched) == patched
    for rel, edits in overlay.EDITS.items():
        for old, new in edits:
            drift = dict(before)
            drift[rel] = drift[rel].replace(old, 'ANCHOR_DRIFT' + old[10:], 1)
            try:
                overlay.patch(drift)
            except ValueError:
                pass
            else:
                raise AssertionError(f'{rel}: changed anchor accepted')
            partial = dict(before)
            partial[rel] = partial[rel].replace(old, new)
            try:
                overlay.patch(partial)
            except ValueError:
                pass
            else:
                raise AssertionError(f'{rel}: partial overlay accepted')

    alias_rel = 'Source/Windows/ARM64EC/IosJitAlias.cpp'
    text = ev.strip_comments(patched[alias_rel])
    window_begin = text.index('static constexpr uint64_t kIosSubfloorFloor')
    window_end = text.index('void BTCpu64IosAddAliasMapping', window_begin)
    window = text[window_begin:window_end].replace('extern "C" ', '')
    entry_begin = text.index('struct IosAliasEntry {')
    entry_end = text.index('constexpr int kMaxEntries = 256;') + len('constexpr int kMaxEntries = 256;')
    data_begin = text.index('IosAliasEntry IosAliasEntries[kMaxEntries];')
    data_end = text.index('}', text.index('IosAliasEntry* volatile IosAliasLast'))
    anon_start = text.index('namespace {', data_end)
    anon_end = ev.match_brace(text, text.index('{', anon_start)) + 1
    production = '\n'.join((
        text[entry_begin:entry_end], text[data_begin:data_end], text[anon_start:anon_end], window,
        ev.body(text, 'void BTCpu64IosAddAliasMapping(uint64_t PeBase, uint64_t JitBase, uint64_t Size) {'),
        ev.body(text, 'uint64_t IosJitTranslate(uint64_t Addr) {'),
        ev.body(text, 'uint64_t IosJitReverseTranslate(uint64_t Addr) {'),
    ))
    build = (ROOT / 'tools/build-xtajit64.sh').read_text()
    apply = 'python3 "$R/tools/patch-fex-ios-guest-windows.py" "$R/FEX"'
    assert build.count(apply) == 1
    assert '\nfi\n' in build[:build.index(apply)]
    assert build.index(apply) < build.index('\nbuild\n', build.index(apply))
    restore = next(line for line in build.splitlines() if line.startswith('git -C FEX checkout --'))
    for rel in overlay.EDITS:
        assert rel in restore, f'not restored after build: {rel}'
    assert 'IosGuestWindowAbi DATA' in patched['Source/Windows/ARM64EC/libarm64ecfex.def']
    # Decoder already separates guest identity and backing bytes (ml954);
    # the operand translator uses 64-bit bases/deltas and no <4GB gate (ml1057).
    frontend = (args.fex_root / 'FEXCore/Source/Interface/Core/Frontend.cpp').read_text()
    assert 'const uint64_t RealRIP = IosSubfloorToReal(RIP);' in frontend
    assert '.AdjustedInstStream = reinterpret_cast<const uint8_t*>(RealRIP)' in frontend
    dispatch = (args.fex_root / 'FEXCore/Source/Interface/Core/OpcodeDispatcher.cpp').read_text()
    assert 'IosXl.Delta = Real - Low;' in dispatch
    assert 'IosSubfloorWindowForCode(RIP, &Low, &Sz, &Real)' in dispatch
    atomic = patched['FEXCore/Source/Interface/Core/OpcodeDispatcher.cpp']
    for line in atomic.splitlines():
        if any(op in line for op in ('_AtomicFetch', '_AtomicSwap(', '_CAS(', '_CASPair(')):
            assert 'IosXlate(' in line, f'atomic bypasses guest-window translation: {line}'
    translate = ev.body(
        patched['FEXCore/Source/Interface/Core/OpcodeDispatcher.h'],
        '  Ref IosXlate(Ref EA, uint64_t AccessBytes = 1) {')
    print('FEX guest windows: pin anchors, idempotence, partial/drift rejection, ABI, decoder and build wiring PASS')
    if args.static_only:
        print('SKIP compiled production helpers (--static-only); no native/device execution')
        return

    source = r'''
#include <cstdint>
#include <atomic>
#include <cassert>
#include <cstdio>
#include <initializer_list>
#include <thread>
namespace LogMan { namespace Msg { template<class... T> void EFmt(T...) {} } }
namespace parent {
''' + production + '\n}\nnamespace child {\n' + production + r'''
}
// Evaluate the actual IR-building expression with uint64 operations. This
// checks address/width semantics without copying its range-test formula.
enum class OpSize { i64Bit };
struct Emitter {
  using Ref = uint64_t;
  struct { bool On; uint64_t Low, Size, Delta; } IosXl;
  Ref Constant(uint64_t X) { return X; }
  Ref Sub(OpSize, Ref A, Ref B) { return A - B; }
  Ref Add(OpSize, Ref A, Ref B) { return A + B; }
  Ref _And(OpSize, Ref A, Ref B) { return A & B; }
  Ref _Andn(OpSize, Ref A, Ref B) { return A & ~B; }
  Ref _Ashr(OpSize, Ref A, Ref B) { return static_cast<int64_t>(A) >> B; }
''' + translate + r'''
};
int main() {
  constexpr uint64_t Guest = 0x140000000ull, Size = 0x200000ull;
  constexpr uint64_t Parent = 0x200000000ull, Child = 0x300000000ull;
  constexpr uint64_t Tag = 1ull << 63;
  assert(parent::IosGuestWindowAbi[0] == 0x314e49574744494dull);
  assert(parent::IosGuestWindowAbi[1] == Tag && parent::IosGuestWindowAbi[2] == 128);
  parent::BTCpu64IosAddAliasMapping(Guest, Parent, Tag | Size);
  child::BTCpu64IosAddAliasMapping(Guest, Child, Tag | Size);
  assert(!parent::IosAliasCount && !child::IosAliasCount);
  for (uint64_t Offset = 0; Offset < Size; Offset += 0x31) {
    assert(parent::IosSubfloorToReal(Guest + Offset) == Parent + Offset);
    assert(child::IosSubfloorToReal(Guest + Offset) == Child + Offset);
    assert(parent::IosSubfloorToLow(Parent + Offset) == Guest + Offset);
    assert(child::IosSubfloorToLow(Child + Offset) == Guest + Offset);
    // Foreign backing must never be interpreted as our image.
    assert(child::IosSubfloorToLow(Parent + Offset) == Parent + Offset);
    assert(parent::IosSubfloorToLow(Child + Offset) == Child + Offset);
    // Module.S's EC table must keep guest control-flow identity unchanged.
    assert(parent::IosJitTranslate(Guest + Offset) == Guest + Offset);
    assert(child::IosJitTranslate(Guest + Offset) == Guest + Offset);
  }
  assert(parent::IosSubfloorToReal(Guest - 1) == Guest - 1);
  assert(parent::IosSubfloorToReal(Guest + Size) == Guest + Size);
  assert(parent::IosSubfloorToReal(UINT64_MAX) == UINT64_MAX);
  assert(parent::IosSubfloorClipSize(Guest + Size - 16, 32) == 16);
  assert(parent::IosSubfloorClipSize(Guest + Size, 32) == 32);
  uint64_t Low, Len, Real;
  assert(parent::IosSubfloorWindowForCode(Guest + 16, &Low, &Len, &Real));
  assert(Low == Guest && Len == Size && Real == Parent);
  assert(parent::IosSubfloorWindowForCode(Parent + 16, &Low, &Len, &Real));
  assert(!parent::IosSubfloorWindowForCode(Child + 16, &Low, &Len, &Real));
  assert(parent::IosSubfloorEnum(0, &Low, &Real, &Len));
  assert(Low == Guest && Len == Size && Real == Parent);
  assert(!parent::IosSubfloorEnum(-1, &Low, &Real, &Len));
  assert(!parent::IosSubfloorEnum(1, &Low, &Real, &Len));
  // Legacy low windows and ordinary EC executable aliases keep their meaning.
  parent::BTCpu64IosAddAliasMapping(0x400000, 0x400000000ull, 0x10000);
  assert(parent::IosSubfloorToReal(0x400030) == 0x400000030ull);
  parent::BTCpu64IosAddAliasMapping(0x500000000ull, 0x600000000ull, 0x10000);
  assert(parent::IosAliasCount == 1);
  assert(parent::IosJitTranslate(0x500000020ull) == 0x600000020ull);
  assert(parent::IosJitReverseTranslate(0x600000020ull) == 0x500000020ull);
  // Invalid tags cannot create alias entries or a wrapped guest range.
  const auto Count = parent::g_SubfloorCount;
  parent::BTCpu64IosAddAliasMapping(0x700000000ull, 0x800000000ull, Tag);
  parent::BTCpu64IosAddAliasMapping(UINT64_MAX - 4096, 0x800000000ull, Tag | 8192);
  parent::BTCpu64IosAddAliasMapping(0x700000000ull, UINT64_MAX - 4096, Tag | 8192);
  parent::BTCpu64IosAddAliasMapping(0x700000000ull, 0x800000000ull, Tag | (1ull << 40));
  assert(parent::g_SubfloorCount == Count && parent::IosAliasCount == 1);
  // Re-registration changes only the registering emulator's backing.
  parent::BTCpu64IosAddAliasMapping(Guest, 0x900000000ull, Tag | Size);
  assert(parent::g_SubfloorCount == Count);
  assert(parent::IosSubfloorToReal(Guest) == 0x900000000ull);
  assert(child::IosSubfloorToReal(Guest) == Child);
  parent::BTCpu64IosAddAliasMapping(Guest, Parent, Tag); // stale release
  assert(parent::IosSubfloorToReal(Guest) == 0x900000000ull);
  parent::BTCpu64IosAddAliasMapping(Guest, 0x900000000ull, Tag);
  assert(parent::IosSubfloorToReal(Guest) == Guest);
  assert(parent::IosSubfloorToLow(0x900000000ull) == 0x900000000ull);
  assert(child::IosSubfloorToReal(Guest) == Child);
  assert(!parent::IosSubfloorWindowForCode(Guest + 16, &Low, &Len, &Real));
  parent::BTCpu64IosAddAliasMapping(Guest, 0x900000000ull, Tag | Size);
  assert(parent::g_SubfloorCount == Count);
  // Explicit capacity refusal must not fall through into executable aliases.
  for (int i = Count; i < 128; ++i)
    parent::BTCpu64IosAddAliasMapping(0x1000000000ull + i * 0x10000ull,
                                     0x2000000000ull + i * 0x10000ull, Tag | 0x1000);
  assert(parent::g_SubfloorCount == 128);
  parent::BTCpu64IosAddAliasMapping(0x1100000000ull, 0x2100000000ull, Tag | 0x1000);
  assert(parent::g_SubfloorCount == 128 && parent::IosAliasCount == 1);
  assert(parent::IosSubfloorToReal(0x1100000000ull) == 0x1100000000ull);
  parent::BTCpu64IosAddAliasMapping(0x1000000000ull + 127 * 0x10000ull,
                                   0x2000000000ull + 127 * 0x10000ull, Tag);
  parent::BTCpu64IosAddAliasMapping(0x1100000000ull, 0x2100000000ull, Tag | 0x1000);
  assert(parent::g_SubfloorCount == 128 && parent::IosAliasCount == 1);
  assert(parent::IosSubfloorToReal(0x1100000000ull) == 0x2100000000ull);
  for (uint64_t Backing : {Parent, uint64_t(0x100000000ull)}) {
    Emitter Emit {{true, Guest, Size, Backing - Guest}};
    for (uint64_t Width : {1ull, 2ull, 4ull, 8ull, 16ull, 32ull, 64ull}) {
      for (int64_t Edge = -65; Edge <= 65; ++Edge) {
        for (uint64_t Address : {Guest + Edge, Guest + Size + Edge, uint64_t(Edge)}) {
          const bool Within = Address >= Guest && Address - Guest < Size &&
                              Width <= Size - (Address - Guest);
          const uint64_t Expected = Within ? Backing + (Address - Guest) : Address;
          assert(Emit.IosXlate(Address, Width) == Expected);
        }
      }
    }
    assert(Emit.IosXlate(Guest, 0) == Guest);
    assert(Emit.IosXlate(Guest, Size + 1) == Guest);
    Emit.IosXl.On = false;
    assert(Emit.IosXlate(Guest + 1, 8) == Guest + 1);
  }
  // Concurrent publishers and readers must not mix the size/backing fields.
  // A snapshot taken during publication may return an empty bounded miss.
  parent::BTCpu64IosAddAliasMapping(Guest, Parent, Tag | Size);
  auto Writer = [=](uint64_t Backing, uint64_t Length) {
    for (int i = 0; i < 100000; ++i)
      parent::BTCpu64IosAddAliasMapping(Guest, Backing, Tag | Length);
  };
  auto Reader = [=] {
    for (int i = 0; i < 200000; ++i) {
      const auto Entry = parent::IosSubfloorSnapshot(0);
      if (!Entry.Size) continue;
      assert(Entry.LowBase == Guest);
      assert((Entry.RealBase == Parent && Entry.Size == Size) ||
             (Entry.RealBase == Child && Entry.Size == Size * 2));
    }
  };
  std::thread First(Writer, Parent, Size), Second(Writer, Child, Size * 2);
  std::thread ReadFirst(Reader), ReadSecond(Reader);
  First.join(); Second.join(); ReadFirst.join(); ReadSecond.join();
  // Simulate a signal interrupting this thread halfway through publication.
  __atomic_add_fetch(&parent::g_Subfloor[0].Generation, uint64_t(1), __ATOMIC_ACQ_REL);
  assert(!parent::IosSubfloorSnapshot(0).Size);
  __atomic_add_fetch(&parent::g_Subfloor[0].Generation, uint64_t(1), __ATOMIC_RELEASE);
  std::puts("FEX guest windows: compiled production helpers PASS (two owners, identity, bounds, tag, capacity, scalar/atomic address IR, concurrent snapshots)");
}
'''
    with tempfile.TemporaryDirectory() as tmp:
        cpp = Path(tmp) / 'guest-windows.cpp'
        exe = Path(tmp) / ('guest-windows.exe' if os.name == 'nt' else 'guest-windows')
        cpp.write_text(source)
        subprocess.run([os.environ.get('CXX', 'c++'), '-std=c++20', '-O1', '-Wall', '-Wextra', '-pthread',
                        str(cpp), '-o', str(exe)], check=True)
        subprocess.run([str(exe)], check=True)


if __name__ == '__main__':
    main()
