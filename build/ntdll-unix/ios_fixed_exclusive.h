/* iDeck-BCD, 2026-10-23: execute a bounded native LL/SC operation on private
 * image backing. No exclusive reservation is carried across a Mach exception.
 * shortcut: only a single register-only ALU and optional B.NE are accepted;
 * extend the decoder with a regression when another native sequence is seen. */
#ifndef IOS_FIXED_EXCLUSIVE_H
#define IOS_FIXED_EXCLUSIVE_H
#include <stdint.h>
#include <string.h>

struct ios_fixed_exclusive {
    unsigned size, base, load, status, value, store;
    uint32_t alu;
    int64_t mismatch;
};

static int ios_fixed_exclusive_alu(uint32_t insn, uint64_t regs[31], uint32_t *flags)
{
    unsigned rd = insn & 31, rn = (insn >> 5) & 31, rm = (insn >> 16) & 31;
    unsigned wide = insn >> 31, setflags = (insn >> 29) & 1;
    uint64_t mask = wide ? UINT64_MAX : UINT32_MAX, sign = (mask >> 1) + 1;
    uint64_t a = rn == 31 ? 0 : regs[rn] & mask, b, result;
    unsigned nzcv = 0;
    int arithmetic = 1, sub = (insn >> 30) & 1;

    if ((insn & 0x1f800000) == 0x11000000) /* ADD/SUB immediate */
    {
        if (rn == 31 || (rd == 31 && !setflags)) return 0; /* SP is not XZR */
        b = (insn >> 10) & 0xfff;
        if (insn & 0x400000) b <<= 12;
    }
    else if ((insn & 0x1fe0fc00) == 0x0b000000) /* ADD/SUB register, LSL #0 */
        b = rm == 31 ? 0 : regs[rm] & mask;
    else if ((insn & 0x1fe0fc00) == 0x0a000000) /* AND/ORR/EOR/ANDS, LSL #0 */
    {
        unsigned op = (insn >> 29) & 3;
        b = rm == 31 ? 0 : regs[rm] & mask;
        result = op == 1 ? a | b : op == 2 ? a ^ b : a & b;
        setflags = op == 3;
        arithmetic = 0;
    }
    else return 0;

    if (arithmetic)
    {
        result = (sub ? a - b : a + b) & mask;
        if (sub ? a >= b : result < a) nzcv |= 2;
        if ((sub ? (a ^ b) & (a ^ result) : ~(a ^ b) & (a ^ result)) & sign) nzcv |= 1;
    }
    if (setflags)
    {
        if (result & sign) nzcv |= 8;
        if (!result) nzcv |= 4;
        *flags = (*flags & 0x0fffffff) | (nzcv << 28);
    }
    if (rd != 31) regs[rd] = result;
    return 1;
}

/* Validate before any data access or register change. The caller additionally
 * verifies that a mismatch branch lands on CLREX, not another store-exclusive. */
static int ios_fixed_exclusive_decode(const uint32_t code[4], struct ios_fixed_exclusive *out)
{
    struct ios_fixed_exclusive p = {0};
    uint64_t scratch[31] = {0};
    uint32_t flags = 0, insn = code[0], st;
    unsigned at = 1;
    if ((insn & 0x3ffffc00) != 0x085ffc00 && (insn & 0x3ffffc00) != 0x085f7c00) return 0;
    p.size = insn >> 30; p.base = (insn >> 5) & 31; p.load = insn & 31;
    if (p.base == 31 || p.load == 31 || p.base == p.load) return 0;
    if (ios_fixed_exclusive_alu(code[at], scratch, &flags))
    {
        p.alu = code[at++];
        if ((p.alu & 31) == p.base || (p.alu >> 31) != (p.size == 3)) return 0;
        if ((code[at] & 0xff00001f) == 0x54000001) /* B.NE */
        {
            /* Only a comparison (SUBS/ADDS to ZR) can exit before the store. */
            if ((p.alu & 0x2000001f) != 0x2000001f ||
                (p.alu & 0x1f000000) == 0x0a000000) return 0;
            int32_t displacement = (int32_t)((code[at] & 0x00ffffe0) << 8) >> 11;
            p.mismatch = (int64_t)at * 4 + displacement;
            if (p.mismatch >= 0 && p.mismatch < 16) return 0;
            ++at;
        }
    }
    st = code[at];
    if ((st & 0x3fe0fc00) != 0x0800fc00 && (st & 0x3fe0fc00) != 0x08007c00) return 0;
    p.status = (st >> 16) & 31; p.value = st & 31; p.store = at;
    if ((st >> 30) != p.size || ((st >> 5) & 31) != p.base ||
        p.status == 31 || p.status == p.base || p.status == p.value) return 0;
    *out = p;
    return 1;
}

/* The entire load/ALU/store is linearized by one real CAS. A competing writer
 * makes STXR fail and the original native retry branch runs unchanged. */
static int64_t ios_fixed_exclusive_run(const struct ios_fixed_exclusive *p, uintptr_t backing,
                                       uint64_t regs[31], uint32_t *flags)
{
    uint64_t loaded = 0, wanted;
    int success = 0;
#define IOS_EXCLUSIVE_LOAD(T) loaded = __atomic_load_n((T *)backing, __ATOMIC_SEQ_CST)
    switch (p->size)
    {
    case 0: IOS_EXCLUSIVE_LOAD(uint8_t); break;
    case 1: IOS_EXCLUSIVE_LOAD(uint16_t); break;
    case 2: IOS_EXCLUSIVE_LOAD(uint32_t); break;
    default: IOS_EXCLUSIVE_LOAD(uint64_t); break;
    }
#undef IOS_EXCLUSIVE_LOAD
    regs[p->load] = loaded;
    if (p->alu) ios_fixed_exclusive_alu(p->alu, regs, flags);
    if (p->mismatch && !(*flags & 0x40000000)) return p->mismatch;
    wanted = p->value == 31 ? 0 : regs[p->value];
#define IOS_EXCLUSIVE_CAS(T) do { T expected = (T)loaded; \
    success = __atomic_compare_exchange_n((T *)backing, &expected, (T)wanted, 0, \
                                          __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST); } while (0)
    switch (p->size)
    {
    case 0: IOS_EXCLUSIVE_CAS(uint8_t); break;
    case 1: IOS_EXCLUSIVE_CAS(uint16_t); break;
    case 2: IOS_EXCLUSIVE_CAS(uint32_t); break;
    default: IOS_EXCLUSIVE_CAS(uint64_t); break;
    }
#undef IOS_EXCLUSIVE_CAS
    regs[p->status] = !success;
    return (p->store + 1) * 4;
}
#endif
