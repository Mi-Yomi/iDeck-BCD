/* iDeck-BCD, 2026-10-23: production decoder/CAS, including the 1C device fault. */
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include "ios_fixed_exclusive.h"

typedef struct { uint64_t regs[29], fp, lr, pc; uint32_t flags; } ucontext_t;
typedef uintptr_t mach_vm_address_t;
typedef size_t mach_vm_size_t;
#define KERN_SUCCESS 0
#define REGn_sig(n,c) ((c)->regs[n])
#define FP_sig(c) ((c)->fp)
#define LR_sig(c) ((c)->lr)
#define PC_sig(c) ((c)->pc)
#define PSTATE_sig(c) ((c)->flags)
static uint32_t native_code[18];
static unsigned read_number, reject_read;
static int mach_task_self(void) { return 1; }
static int mach_vm_read_overwrite(int task, uintptr_t source, size_t size, uintptr_t dest, size_t *got)
{
    assert(task == 1 && size == 4);
    if (++read_number == reject_read || source < (uintptr_t)native_code ||
        source > (uintptr_t)(native_code + 18) - size) return 1;
    memcpy((void *)dest, (void *)source, size); *got = size; return 0;
}
#include "fixed-service.inc"

static _Alignas(16) uint64_t word;
static const uint32_t lock_code[4] = {0x885ffd09, 0x3100053f, 0x540001e1, 0x8809fd1f};
static const uint32_t add_code[4] = {0x885ffd09, 0x1100052a, 0x880bfd0a, 0x35ffffab};

static void exception_service(void)
{
    ucontext_t ctx = {0};
    memcpy(native_code, lock_code, sizeof(lock_code));
    native_code[17] = 0xd5033f5f; /* CLREX at the actual mismatch destination. */
    ctx.pc = (uintptr_t)native_code; ctx.regs[8] = 0x14005fa00;
    ctx.fp = 0x1234; ctx.lr = 0x5678;
    ucontext_t initial = ctx;
    word = UINT32_MAX;
    assert(ios_service_fixed_exclusive(&ctx, 0x14005fa00, (uintptr_t)&word));
    assert(ctx.pc + 4 == initial.pc + 16 && ctx.regs[9] == 0 && !word);
    assert(ctx.fp == initial.fp && ctx.lr == initial.lr && ctx.flags == 0x60000000);
    ctx = initial; word = 7;
    assert(ios_service_fixed_exclusive(&ctx, 0x14005fa00, (uintptr_t)&word));
    assert(ctx.pc + 4 == initial.pc + 0x44 && ctx.regs[9] == 7 && word == 7);
    for (reject_read = 1; reject_read <= 5; ++reject_read)
    {
        ctx = initial; word = UINT32_MAX; read_number = 0;
        assert(!ios_service_fixed_exclusive(&ctx, 0x14005fa00, (uintptr_t)&word));
        assert(!memcmp(&ctx, &initial, sizeof(ctx)) && word == UINT32_MAX);
    }
    reject_read = 0;
    ctx = initial;
    assert(!ios_service_fixed_exclusive(&ctx, 0x14005fa04, (uintptr_t)&word));
    assert(!ios_service_fixed_exclusive(&ctx, 0x14005fa00, (uintptr_t)&word + 1));
    native_code[17] = 0xd503201f; /* Do not carry a reservation to an unknown exit. */
    assert(!ios_service_fixed_exclusive(&ctx, 0x14005fa00, (uintptr_t)&word));
    assert(!memcmp(&ctx, &initial, sizeof(ctx)) && word == UINT32_MAX);
}

static void compare_exchange(void)
{
    struct ios_fixed_exclusive p;
    uint64_t regs[31] = {0};
    uint32_t flags = 0x12345;
    assert(ios_fixed_exclusive_decode(lock_code, &p));
    assert(p.base == 8 && p.load == 9 && p.status == 9 && p.mismatch == 0x44);
    word = UINT32_MAX;
    regs[8] = 0x14005fa00;
    assert(ios_fixed_exclusive_run(&p, (uintptr_t)&word, regs, &flags) == 16);
    assert(word == 0 && regs[9] == 0 && flags == 0x60012345);
    assert(regs[8] == 0x14005fa00); /* Never replace a guest pointer with backing. */
    word = 7; flags = 0x12345;
    assert(ios_fixed_exclusive_run(&p, (uintptr_t)&word, regs, &flags) == 0x44);
    assert(word == 7 && regs[9] == 7 && flags == 0x12345);
    word = 0x7fffffff;
    assert(ios_fixed_exclusive_run(&p, (uintptr_t)&word, regs, &flags) == 0x44);
    assert(flags == 0x90012345); /* CMN overflow, negative result. */
}

static void widths_and_flags(void)
{
    for (unsigned size = 0; size < 4; ++size)
    {
        uint32_t code[4] = {0x085ffd09 | size << 30, 0x080afd0b | size << 30, 0, 0};
        struct ios_fixed_exclusive p;
        uint64_t regs[31] = {0}, mask = size == 3 ? UINT64_MAX : (1ULL << (8u << size)) - 1;
        uint32_t flags = 0x81234567;
        assert(ios_fixed_exclusive_decode(code, &p));
        word = UINT64_MAX; regs[11] = 0x123456789abcdef0ULL;
        assert(ios_fixed_exclusive_run(&p, (uintptr_t)&word, regs, &flags) == 8);
        assert(regs[9] == mask && regs[10] == 0 && flags == 0x81234567);
        assert(word == ((UINT64_MAX & ~mask) | (regs[11] & mask)));
    }
    uint64_t regs[31] = {0};
    uint32_t flags = 0x12345;
    regs[9] = 0x80000000;
    assert(ios_fixed_exclusive_alu(0x71000529, regs, &flags)); /* SUBS W9,W9,#1 */
    assert(regs[9] == 0x7fffffff && flags == 0x30012345);
    regs[9] = UINT64_MAX;
    assert(ios_fixed_exclusive_alu(0xb1000529, regs, &flags)); /* ADDS X9,X9,#1 */
    assert(regs[9] == 0 && flags == 0x60012345);
    regs[9] = 0xf0; regs[10] = 0x0f;
    assert(ios_fixed_exclusive_alu(0x6a0a0129, regs, &flags)); /* ANDS W9,W9,W10 */
    assert(regs[9] == 0 && flags == 0x40012345);
}

static void refusals(void)
{
    struct ios_fixed_exclusive p;
    uint32_t code[4];
    const struct { unsigned at; uint32_t insn; } bad[] = {
        {0, 0x885ffd08}, /* load overwrites address */
        {0, 0x885fffE9}, /* SP base */
        {1, 0x9100053f}, /* ADD to SP */
        {1, 0x31000528}, /* ALU overwrites address */
        {2, 0x540001e0}, /* unsupported B.EQ */
        {2, 0x54000021}, /* branch into the operation */
        {3, 0xc809fd1f}, /* mismatching width */
        {3, 0x8809fd3f}, /* mismatching address */
        {3, 0x8808fd1f}, /* status overwrites address */
        {3, 0x880ffd0f}, /* status aliases value */
        {1, 0xf9400129}, /* another memory access */
        {1, 0x94000000}, /* call */
        {1, 0xd503201f}, /* unsupported NOP */
    };
    for (unsigned i = 0; i < sizeof(bad)/sizeof(bad[0]); ++i)
    {
        memcpy(code, lock_code, sizeof(code)); code[bad[i].at] = bad[i].insn;
        memset(&p, 0x55, sizeof(p));
        struct ios_fixed_exclusive before = p;
        assert(!ios_fixed_exclusive_decode(code, &p));
        assert(!memcmp(&p, &before, sizeof(p)));
    }
}

static void *increments(void *unused)
{
    struct ios_fixed_exclusive p;
    uint64_t regs[31] = {0};
    uint32_t flags = 0;
    (void)unused;
    assert(ios_fixed_exclusive_decode(add_code, &p));
    for (unsigned i = 0; i < 30000; ++i)
        do { assert(ios_fixed_exclusive_run(&p, (uintptr_t)&word, regs, &flags) == 12); }
        while (regs[11]);
    return NULL;
}

int main(void)
{
    pthread_t threads[3];
    exception_service(); compare_exchange(); widths_and_flags(); refusals();
    word = 0;
    for (unsigned i = 0; i < 3; ++i) assert(!pthread_create(&threads[i], NULL, increments, NULL));
    for (unsigned i = 0; i < 30000; ++i) __atomic_fetch_add((uint32_t *)&word, 1, __ATOMIC_SEQ_CST);
    for (unsigned i = 0; i < 3; ++i) assert(!pthread_join(threads[i], NULL));
    assert(word == 120000);
    puts("PASS: native LL/SC device sequence, compare outcomes, widths, NZCV, refusal and concurrent CAS updates");
    return 0;
}
