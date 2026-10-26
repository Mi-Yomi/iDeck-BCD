#!/usr/bin/env python3
"""iDeck, 2026-10-22: process-private fixed-image guest windows for ARM64EC.

Keep a fixed x64 image's original virtual addresses while its bytes live in a
private backing allocation. Reuse the existing ml951/ml954/ml1057 machinery
(query, decode and data operand translation), but accept explicit windows above
4 GiB. These entries MUST NOT reach the native EC branch-target alias table.

The existing three-argument callback carries a tagged Size (bit 63). The unix
side must verify the IosGuestWindowAbi DATA export on the registering process's
own emulator before sending the tag. No PE function is called via a raw export
and the one-pointer unix-call ABI is unchanged. Native reservation, owner and
fallback handling are in the parent repository; this overlay alone enables
nothing. The native opt-in is MADEIRA_FIXED_IMAGE_ISOLATION=1.

This is a local build overlay, not a contribution to FEX. The gitlink and pinned
sources remain unchanged. Applied after the other xtajit64 overlays.
"""
from pathlib import Path
import sys

MARKER = "ideck-guest-windows-v1"
SUMMARY = "FEX ARM64EC: versioned process-private guest windows (opt-in on unix side)"

EDITS = {
    "Source/Windows/ARM64EC/IosJitAlias.cpp": (
        (
'''static constexpr uint64_t kIosSubfloorFloor = 0x100000000ull;
static constexpr int kMaxSubfloorEntries = 8;
''',
'''static constexpr uint64_t kIosSubfloorFloor = 0x100000000ull;
// ideck-guest-windows-v1, 2026-10-22. A tagged Size is a guest window,
// never an EC execution alias. Each private emulator owns this table.
static constexpr uint64_t kIosGuestWindowTag = 1ull << 63;
static constexpr int kMaxSubfloorEntries = 128;
extern const uint64_t IosGuestWindowAbi[3] = {
  0x314e49574744494dull, kIosGuestWindowTag, kMaxSubfloorEntries,
};
static uint64_t g_SubfloorHigh = kIosSubfloorFloor;
''',
        ),
        (
'''struct IosSubfloorEntry {
  uint64_t LowBase;   // what the guest uses (below the floor)
  uint64_t RealBase;  // where the image actually is
  uint64_t Size;
  uint64_t _Padding;
};
static IosSubfloorEntry g_Subfloor[kMaxSubfloorEntries];
static int g_SubfloorCount;

// low -> real, or Addr unchanged when it is not in a window.
uint64_t IosSubfloorToReal(uint64_t Addr) {
  if (Addr >= kIosSubfloorFloor) {
    return Addr; // fast reject: the overwhelmingly common case
  }
  const int count = g_SubfloorCount;
  for (int i = 0; i < count; i++) {
    const uint64_t lb = g_Subfloor[i].LowBase;
    const uint64_t sz = g_Subfloor[i].Size;
    if (sz && Addr >= lb && Addr < lb + sz) {
      return g_Subfloor[i].RealBase + (Addr - lb);
    }
  }
  return Addr;
}

// ml1057: is this guest RIP code that belongs to a sub-floor image -- either at the
// image's real (high) mapping, which is where it executes, or named by its low
// address? If so report the window so the JIT can translate that image's own
// memory operands inline instead of faulting on each one.
extern "C" int IosSubfloorWindowForCode(uint64_t Rip, uint64_t* Low, uint64_t* Size, uint64_t* Real) {
  const int count = g_SubfloorCount;
  for (int i = 0; i < count; i++) {
    const uint64_t lb = g_Subfloor[i].LowBase, rb = g_Subfloor[i].RealBase, sz = g_Subfloor[i].Size;
    if (!sz || !rb) continue;
    if ((Rip >= rb && Rip < rb + sz) || (Rip >= lb && Rip < lb + sz)) {
      static std::atomic<int> Said {0};
      if (Said.fetch_add(1, std::memory_order_relaxed) < 4) {
        LogMan::Msg::EFmt("[iOS-subfloor-xlate] ml1057 block at {:#x} lives in window [{:#x},+{:#x}) -> {:#x}: translating its "
                          "memory operands inline", Rip, lb, sz, rb);
      }
      *Low = lb; *Size = sz; *Real = rb;
      return 1;
    }
  }
  return 0;
}

// real -> low, or Addr unchanged. Used to map a tracker result back into the
// guest's own address domain so the guest RIP is never moved high.
uint64_t IosSubfloorToLow(uint64_t Addr) {
  const int count = g_SubfloorCount;
  for (int i = 0; i < count; i++) {
    const uint64_t rb = g_Subfloor[i].RealBase;
    const uint64_t sz = g_Subfloor[i].Size;
    if (sz && Addr >= rb && Addr < rb + sz) {
      return g_Subfloor[i].LowBase + (Addr - rb);
    }
  }
  return Addr;
}

// ml1207: window Index as {low, real, size}; 0 past the end. The invalidation
// tracker uses it to drop a sub-floor image's code under both of its names.
int IosSubfloorEnum(int Index, uint64_t* Low, uint64_t* Real, uint64_t* Size) {
  if (Index < 0 || Index >= g_SubfloorCount) {
    return 0;
  }
  *Low = g_Subfloor[Index].LowBase;
  *Real = g_Subfloor[Index].RealBase;
  *Size = g_Subfloor[Index].Size;
  return 1;
}

// Clip a range to the end of the window containing LowAddr, so a tracker range
// can never be reported as extending past the window we actually back.
uint64_t IosSubfloorClipSize(uint64_t LowAddr, uint64_t Size) {
  const int count = g_SubfloorCount;
  for (int i = 0; i < count; i++) {
    const uint64_t lb = g_Subfloor[i].LowBase;
    const uint64_t sz = g_Subfloor[i].Size;
    if (sz && LowAddr >= lb && LowAddr < lb + sz) {
      const uint64_t avail = (lb + sz) - LowAddr;
      return Size < avail ? Size : avail;
    }
  }
  return Size;
}

static bool IosSubfloorAdd(uint64_t LowBase, uint64_t RealBase, uint64_t Size) {
  const int count = g_SubfloorCount;
  for (int i = 0; i < count; i++) {
    if (g_Subfloor[i].LowBase == LowBase) {
      // Re-registration: a second pseudo-process mapped the same image. Last
      // writer wins, which is unsafe with two live loaders -- see the ml938
      // note; ownership is owed before this is durable.
      g_Subfloor[i].RealBase = RealBase;
      __sync_synchronize();
      g_Subfloor[i].Size = Size;
      return true;
    }
  }
  if (count >= kMaxSubfloorEntries) {
    return false;
  }
  g_Subfloor[count].LowBase = LowBase;
  g_Subfloor[count].RealBase = RealBase;
  __sync_synchronize();
  g_Subfloor[count].Size = Size; // published last
  g_SubfloorCount = count + 1;
  return true;
}
''',
'''struct IosSubfloorEntry {
  uint64_t LowBase;
  uint64_t RealBase;
  uint64_t Size;
  uint64_t Generation;
};
static IosSubfloorEntry g_Subfloor[kMaxSubfloorEntries];
static int g_SubfloorCount;
static std::atomic_flag g_SubfloorWriter = ATOMIC_FLAG_INIT;

// Publishers neither allocate, log nor call out. Serialize them so a reused
// slot has one odd generation while its three fields are being replaced.
struct IosSubfloorWriteGuard {
  IosSubfloorWriteGuard() {
    while (g_SubfloorWriter.test_and_set(std::memory_order_acquire)) {}
  }
  ~IosSubfloorWriteGuard() { g_SubfloorWriter.clear(std::memory_order_release); }
};

static IosSubfloorEntry IosSubfloorSnapshot(int Index) {
  IosSubfloorEntry Result {};
  const auto& Entry = g_Subfloor[Index];
  // A signal can interrupt a publisher on this thread. Never wait for that
  // interrupted writer: a bounded miss leaves the normal fault path in charge.
  for (int Attempt = 0; Attempt < 3; ++Attempt) {
    const uint64_t Before = __atomic_load_n(&Entry.Generation, __ATOMIC_ACQUIRE);
    if (Before & 1) continue;
    Result.LowBase = __atomic_load_n(&Entry.LowBase, __ATOMIC_RELAXED);
    Result.RealBase = __atomic_load_n(&Entry.RealBase, __ATOMIC_RELAXED);
    Result.Size = __atomic_load_n(&Entry.Size, __ATOMIC_RELAXED);
    __atomic_thread_fence(__ATOMIC_ACQUIRE);
    if (Before == __atomic_load_n(&Entry.Generation, __ATOMIC_RELAXED)) return Result;
  }
  return {};
}

static void IosSubfloorPublish(int Index, uint64_t Low, uint64_t Real, uint64_t Size) {
  auto& Entry = g_Subfloor[Index];
  __atomic_add_fetch(&Entry.Generation, uint64_t(1), __ATOMIC_ACQ_REL);
  __atomic_store_n(&Entry.LowBase, Low, __ATOMIC_RELAXED);
  __atomic_store_n(&Entry.RealBase, Real, __ATOMIC_RELAXED);
  __atomic_store_n(&Entry.Size, Size, __ATOMIC_RELAXED);
  __atomic_add_fetch(&Entry.Generation, uint64_t(1), __ATOMIC_RELEASE);
}

uint64_t IosSubfloorToReal(uint64_t Addr) {
  if (Addr >= __atomic_load_n(&g_SubfloorHigh, __ATOMIC_ACQUIRE)) return Addr;
  const int Count = __atomic_load_n(&g_SubfloorCount, __ATOMIC_ACQUIRE);
  for (int i = 0; i < Count; ++i) {
    const auto Entry = IosSubfloorSnapshot(i);
    if (Entry.Size && Addr >= Entry.LowBase && Addr - Entry.LowBase < Entry.Size)
      return Entry.RealBase + (Addr - Entry.LowBase);
  }
  return Addr;
}

extern "C" int IosSubfloorWindowForCode(uint64_t Rip, uint64_t* Low, uint64_t* Size, uint64_t* Real) {
  const int Count = __atomic_load_n(&g_SubfloorCount, __ATOMIC_ACQUIRE);
  for (int i = 0; i < Count; ++i) {
    const auto Entry = IosSubfloorSnapshot(i);
    if (!Entry.Size || !Entry.RealBase) continue;
    if ((Rip >= Entry.RealBase && Rip - Entry.RealBase < Entry.Size) ||
        (Rip >= Entry.LowBase && Rip - Entry.LowBase < Entry.Size)) {
      *Low = Entry.LowBase;
      *Size = Entry.Size;
      *Real = Entry.RealBase;
      return 1;
    }
  }
  return 0;
}

uint64_t IosSubfloorToLow(uint64_t Addr) {
  const int Count = __atomic_load_n(&g_SubfloorCount, __ATOMIC_ACQUIRE);
  for (int i = 0; i < Count; ++i) {
    const auto Entry = IosSubfloorSnapshot(i);
    if (Entry.Size && Addr >= Entry.RealBase && Addr - Entry.RealBase < Entry.Size)
      return Entry.LowBase + (Addr - Entry.RealBase);
  }
  return Addr;
}

int IosSubfloorEnum(int Index, uint64_t* Low, uint64_t* Real, uint64_t* Size) {
  if (Index < 0 || Index >= __atomic_load_n(&g_SubfloorCount, __ATOMIC_ACQUIRE)) return 0;
  const auto Entry = IosSubfloorSnapshot(Index);
  *Low = Entry.LowBase;
  *Real = Entry.RealBase;
  *Size = Entry.Size;
  return 1;
}

uint64_t IosSubfloorClipSize(uint64_t LowAddr, uint64_t Size) {
  const int Count = __atomic_load_n(&g_SubfloorCount, __ATOMIC_ACQUIRE);
  for (int i = 0; i < Count; ++i) {
    const auto Entry = IosSubfloorSnapshot(i);
    if (Entry.Size && LowAddr >= Entry.LowBase && LowAddr - Entry.LowBase < Entry.Size) {
      const uint64_t Available = Entry.Size - (LowAddr - Entry.LowBase);
      return Size < Available ? Size : Available;
    }
  }
  return Size;
}

static bool IosSubfloorAdd(uint64_t LowBase, uint64_t RealBase, uint64_t Size) {
  constexpr uint64_t Limit = 1ull << 47;
  if (!Size || !RealBase || Size >= (1ull << 40) || LowBase >= Limit || RealBase >= Limit ||
      Size > Limit - LowBase || Size > Limit - RealBase || LowBase == RealBase) return false;
  IosSubfloorWriteGuard Guard;
  uint64_t High = __atomic_load_n(&g_SubfloorHigh, __ATOMIC_RELAXED);
  if (LowBase + Size > High)
    __atomic_store_n(&g_SubfloorHigh, LowBase + Size, __ATOMIC_RELEASE);
  const int Count = __atomic_load_n(&g_SubfloorCount, __ATOMIC_RELAXED);
  int Slot = -1;
  for (int i = 0; i < Count; ++i) {
    const auto Entry = IosSubfloorSnapshot(i);
    if (Entry.LowBase == LowBase) {
      IosSubfloorPublish(i, LowBase, RealBase, Size);
      return true;
    }
    if (!Entry.Size && Slot < 0) Slot = i;
  }
  if (Slot < 0) Slot = Count;
  if (Slot >= kMaxSubfloorEntries) return false;
  IosSubfloorPublish(Slot, LowBase, RealBase, Size);
  if (Slot == Count) __atomic_store_n(&g_SubfloorCount, Count + 1, __ATOMIC_RELEASE);
  return true;
}

static void IosSubfloorRemove(uint64_t Guest, uint64_t Real) {
  // Unmap invalidated both cache identities before reaching this callback.
  // Exact backing match prevents a late cleanup from retiring a replacement.
  IosSubfloorWriteGuard Guard;
  const int Count = __atomic_load_n(&g_SubfloorCount, __ATOMIC_RELAXED);
  for (int i = 0; i < Count; ++i) {
    const auto Entry = IosSubfloorSnapshot(i);
    if (Entry.LowBase == Guest && Entry.RealBase == Real) {
      IosSubfloorPublish(i, Guest, Real, 0);
      return;
    }
  }
}

''',
        ),
        (
'''void BTCpu64IosAddAliasMapping(uint64_t PeBase, uint64_t JitBase, uint64_t Size) {
''',
'''void BTCpu64IosAddAliasMapping(uint64_t PeBase, uint64_t JitBase, uint64_t Size) {
  // The sender has checked IosGuestWindowAbi on THIS emulator before sending
  // a high window. Do this before the legacy low-address discriminator.
  if (Size & kIosGuestWindowTag) {
    Size &= ~kIosGuestWindowTag;
    if (Size) IosSubfloorAdd(PeBase, JitBase, Size);
    else IosSubfloorRemove(PeBase, JitBase);
    return;
  }
''',
        ),
    ),
    "Source/Windows/ARM64EC/libarm64ecfex.def": (
        (
'''  BTCpu64IosAddAliasMapping
''',
'''  BTCpu64IosAddAliasMapping
  ; iDeck 2026-10-22: explicit guest-window callback capability, version 1
  IosGuestWindowAbi DATA
''',
        ),
    ),
    "Source/Windows/ARM64EC/Module.cpp": (
        (
'''void HandleImageMap(uint64_t Address, bool MainImage = false) {
''',
'''// The Windows-facing ABI reports guest addresses, while image bytes and
// page protection live at the private backing address (iDeck 2026-10-22).
static uint64_t IosImageBacking(uint64_t Address) {
#ifdef FEX_IOS_HOST
  return IosSubfloorToReal(Address);
#else
  return Address;
#endif
}

void HandleImageMap(uint64_t Address, bool MainImage = false) {
''',
        ),
        (
'''  InvalidationTracker->HandleImageMap(ModuleName, Address);
  ImageTracker->HandleImageMap(ModulePath, Address, MainImage);
''',
'''  Address = IosImageBacking(Address); // resolve filename before leaving the guest domain
  InvalidationTracker->HandleImageMap(ModuleName, Address);
  ImageTracker->HandleImageMap(ModulePath, Address, MainImage);
''',
        ),
        (
'''InvalidationTracker->HandleImageMap(ModuleName, reinterpret_cast<uint64_t>(Address));''',
'''InvalidationTracker->HandleImageMap(ModuleName, IosImageBacking(reinterpret_cast<uint64_t>(Address)));''',
        ),
        (
'''InvalidationTracker->HandleMemoryProtectionNotification(reinterpret_cast<uint64_t>(Address), static_cast<uint64_t>(Size), Prot);''',
'''InvalidationTracker->HandleMemoryProtectionNotification(IosImageBacking(reinterpret_cast<uint64_t>(Address)), static_cast<uint64_t>(Size), Prot);''',
        ),
        (
'''InvalidationTracker->HandleMemoryProtectionNotification(reinterpret_cast<uint64_t>(Address), static_cast<uint64_t>(Size), NewProt);''',
'''InvalidationTracker->HandleMemoryProtectionNotification(IosImageBacking(reinterpret_cast<uint64_t>(Address)), static_cast<uint64_t>(Size), NewProt);''',
        ),
        (
'''InvalidationTracker->InvalidateAlignedInterval(reinterpret_cast<uint64_t>(Address), static_cast<uint64_t>(Size), true);''',
'''InvalidationTracker->InvalidateAlignedInterval(IosImageBacking(reinterpret_cast<uint64_t>(Address)), static_cast<uint64_t>(Size), true);''',
        ),
        (
'''InvalidationTracker->InvalidateContainingSection(reinterpret_cast<uint64_t>(Address), true);''',
'''InvalidationTracker->InvalidateContainingSection(IosImageBacking(reinterpret_cast<uint64_t>(Address)), true);''',
        ),
        (
'''    if (InvalidationTracker && InvalidationTracker->HandleRWXAccessViolation(Thread, NativeContext->Pc, FaultAddress)) {''',
'''    if (InvalidationTracker && InvalidationTracker->HandleRWXAccessViolation(Thread, NativeContext->Pc, IosImageBacking(FaultAddress))) {''',
        ),
        (
'''CTX->IsAddressInCurrentBlock(Thread, FaultAddress & FEXCore::Utils::FEX_PAGE_MASK, FEXCore::Utils::FEX_PAGE_SIZE))''',
'''CTX->IsAddressInCurrentBlock(Thread,
#ifdef FEX_IOS_HOST
                                      IosSubfloorToLow(FaultAddress) & FEXCore::Utils::FEX_PAGE_MASK,
#else
                                      FaultAddress & FEXCore::Utils::FEX_PAGE_MASK,
#endif
                                      FEXCore::Utils::FEX_PAGE_SIZE))''',
        ),
        (
'''        const uint64_t SmcPc = NativeContext->Pc;
''',
'''        // Private image backing can actually become writable. Retry the
        // original instruction; guest-domain accesses re-enter the owner-aware
        // fault path. Do not rewrite release stores or split atomic accesses.
        if (IosSubfloorToReal(FaultAddress) != FaultAddress || IosSubfloorToLow(FaultAddress) != FaultAddress) {
          return true;
        }
        const uint64_t SmcPc = NativeContext->Pc;
''',
        ),
        (
'''    auto Result = ImageTracker->LookupExecutableFileSection(Address);
#ifdef FEX_IOS_HOST
''',
'''#ifdef FEX_IOS_HOST
    // ideck-guest-windows-v1: section metadata stays in the guest domain;
    // image bytes and relocation records belong to this process's backing.
    const uint64_t RealAddress = IosSubfloorToReal(Address);
    if (RealAddress != Address) {
      auto Result = ImageTracker->LookupExecutableFileSection(RealAddress);
      if (Result.has_value()) {
        Result->FileStartVA = IosSubfloorToLow(Result->FileStartVA);
        Result->BeginVA = IosSubfloorToLow(Result->BeginVA);
        Result->EndVA = IosSubfloorToLow(Result->EndVA - 1) + 1;
      }
      return Result;
    }
#endif
    auto Result = ImageTracker->LookupExecutableFileSection(Address);
#ifdef FEX_IOS_HOST
''',
        ),
        (
'''    InvalidationTracker->ReprotectRWXIntervals(Start, Length);
''',
'''#ifdef FEX_IOS_HOST
    // Reprotect the actual pages. Cache identities remain guest addresses;
    // InvalidateIntervalInternalLocked invalidates both names (ml1207).
    const uint64_t RealStart = IosSubfloorToReal(Start);
    if (RealStart != Start) {
      Length = IosSubfloorClipSize(Start, Length);
      Start = RealStart;
    }
#endif
    InvalidationTracker->ReprotectRWXIntervals(Start, Length);
''',
        ),
        (
'''    auto Result = InvalidationTracker->QueryExecutableRange(Address);
#ifdef FEX_IOS_HOST
''',
'''#ifdef FEX_IOS_HOST
    // A high guest window is deliberately reserved PROT_NONE. Its executable
    // status comes exclusively from the owner's backing, even if a tracker
    // retained a stale range at the guest address.
    const uint64_t WindowAddress = IosSubfloorToReal(Address);
    if (WindowAddress != Address) {
      auto Inner = InvalidationTracker->QueryExecutableRange(WindowAddress);
      if (!Inner.Size) return Inner;
      const uint64_t GuestBase = IosSubfloorToLow(Inner.Base);
      if (GuestBase == Inner.Base) return {};
      return {GuestBase, IosSubfloorClipSize(GuestBase, Inner.Size), Inner.Writable};
    }
#endif
    auto Result = InvalidationTracker->QueryExecutableRange(Address);
#ifdef FEX_IOS_HOST
''',
        ),
    ),
    "FEXCore/Source/Interface/Core/OpcodeDispatcher.h": (
        (
'''  Ref IosXlate(Ref EA) {
    if (!IosXl.On) return EA;
    Ref T = Sub(OpSize::i64Bit, EA, Constant(IosXl.Low));          // >= 2^63 when EA < Low
    Ref U = Sub(OpSize::i64Bit, T, Constant(IosXl.Size));          // top bit set when T < Size (or T huge)
''',
'''  Ref IosXlate(Ref EA, uint64_t AccessBytes = 1) {
    if (!IosXl.On || !AccessBytes || AccessBytes > IosXl.Size) return EA;
    // ideck-guest-windows-v1: translate only a wholly-contained access. A
    // cross-boundary operand must fault instead of touching adjacent backing.
    const uint64_t Starts = IosXl.Size - AccessBytes + 1;
    Ref T = Sub(OpSize::i64Bit, EA, Constant(IosXl.Low));          // >= 2^63 when EA < Low
    Ref U = Sub(OpSize::i64Bit, T, Constant(Starts));             // valid starting offsets only
''',
        ),
        ('    Addr = IosXlate(Addr);\n', '    Addr = IosXlate(Addr, IR::OpSizeToSize(Size));\n'),
        ('    ssa0 = IosXlate(ssa0);\n', '    ssa0 = IosXlate(ssa0, IR::OpSizeToSize(Size));\n'),
        (
'''      Ref EA = IosXlate(LoadEffectiveAddress(this, A, GetGPROpSize(), true));
''',
'''      Ref EA = IosXlate(LoadEffectiveAddress(this, A, GetGPROpSize(), true), IR::OpSizeToSize(Size));
''',
        ),
        (
'''    if (!AtomicTSO && !A.Segment && Size >= OpSize::i32Bit && Size <= OpSize::i128Bit) {
''',
'''    if (!IosXl.On && !AtomicTSO && !A.Segment && Size >= OpSize::i32Bit && Size <= OpSize::i128Bit) {
''',
        ),
    ),
}

# Fixed-image locks must remain real host atomics against the owner's backing;
# servicing the load and store independently in a signal handler is not atomic.
# Keep a literal, audited address operand for every scalar frontend atomic.
EDITS["FEXCore/Source/Interface/Core/OpcodeDispatcher.cpp"] = tuple(
    (old, old.replace(address, f"IosXlate({address}, {width})"))
    for old, address, width in (
        ('_AtomicFetchAdd(Size, ALUOp, DestMem)', 'DestMem', 'IR::OpSizeToSize(Size)'),
        ('_AtomicFetchSub(Size, SrcPlusCF, DestMem)', 'DestMem', 'IR::OpSizeToSize(Size)'),
        ('_AtomicSwap(OpSizeFromSrc(Op), Src, Dest)', 'Dest', 'IR::OpSizeToSize(OpSizeFromSrc(Op))'),
        ('_AtomicFetchCLR(OpSize::i8Bit, BitMask, LoadEffectiveAddress(this, Address, GetGPROpSize(), true))',
         'LoadEffectiveAddress(this, Address, GetGPROpSize(), true)', '1'),
        ('_AtomicFetchOr(OpSize::i8Bit, BitMask, LoadEffectiveAddress(this, Address, GetGPROpSize(), true))',
         'LoadEffectiveAddress(this, Address, GetGPROpSize(), true)', '1'),
        ('_AtomicFetchXor(OpSize::i8Bit, BitMask, LoadEffectiveAddress(this, Address, GetGPROpSize(), true))',
         'LoadEffectiveAddress(this, Address, GetGPROpSize(), true)', '1'),
        ('_AtomicFetchXor(Size, MaskConst, DestMem)', 'DestMem', 'IR::OpSizeToSize(Size)'),
        ('_AtomicFetchAdd(OpSizeFromSrc(Op), Src, Dest)', 'Dest', 'IR::OpSizeToSize(OpSizeFromSrc(Op))'),
        ('_AtomicFetchAdd(OpSizeFromSrc(Op), Constant(1), DestAddress)', 'DestAddress', 'IR::OpSizeToSize(OpSizeFromSrc(Op))'),
        ('_AtomicFetchAdd(OpSizeFromSrc(Op), Constant(Size == 64 ? -1 : ((1ULL << Size) - 1)), DestAddress)',
         'DestAddress', 'IR::OpSizeToSize(OpSizeFromSrc(Op))'),
        ('_AtomicFetchNeg(Size, DestMem)', 'DestMem', 'IR::OpSizeToSize(Size)'),
        ('_CAS(Size, Src3, Src2, Src1)', 'Src1', 'IR::OpSizeToSize(Size)'),
        ('_CASPair(Size, Expected_Lower, Expected_Upper, Desired_Lower, Desired_Upper, Src1, Result_Lower, Result_Upper)',
         'Src1', '2 * IR::OpSizeToSize(Size)'),
        ('_AtomicFetchAdd(Size, Src, DestMem)', 'DestMem', 'IR::OpSizeToSize(Size)'),
    )
)


def expected_count(rel, old):
    if rel.endswith('Module.cpp') and old == 'InvalidationTracker->HandleImageMap(ModuleName, reinterpret_cast<uint64_t>(Address));':
        return 2
    if rel.endswith('OpcodeDispatcher.h') and (
        'if (!AtomicTSO && !A.Segment' in old or
        'Ref EA = IosXlate(LoadEffectiveAddress' in old
    ):
        return 2
    return 1


def patch(sources):
    """Return patched text; refuse changed anchors and partial overlays."""
    results = {}
    for rel, edits in EDITS.items():
        source = sources[rel]
        done = [source.count(new) == expected_count(rel, old) and (old in new or old not in source)
                for old, new in edits]
        if all(done):
            results[rel] = source
            continue
        if any(done):
            raise ValueError(f"{rel}: partial guest-window overlay")
        text = source
        for old, new in edits:
            # The two pair-memory paths intentionally share the same anchor.
            count = expected_count(rel, old)
            if text.count(old) != count or (new in text and new not in old):
                first = old.strip().splitlines()[0]
                raise ValueError(f"{rel}: anchor changed/partial overlay: {first[:100]}")
            text = text.replace(old, new)
        results[rel] = text
    # Across files a partial application is not silently accepted.
    changed = [results[rel] != sources[rel] for rel in EDITS]
    if any(changed) and not all(changed):
        raise ValueError("partial guest-window overlay")
    return results


def main(argv):
    if len(argv) != 2:
        print(f"usage: {argv[0]} <FEX source root>", file=sys.stderr)
        return 2
    root = Path(argv[1])
    sources = {rel: (root / rel).read_text() for rel in EDITS}
    try:
        result = patch(sources)
    except ValueError as error:
        print(f"{Path(argv[0]).name}: {error}", file=sys.stderr)
        return 1
    for rel, text in result.items():
        if text != sources[rel]:
            (root / rel).write_text(text)
    print(SUMMARY)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
