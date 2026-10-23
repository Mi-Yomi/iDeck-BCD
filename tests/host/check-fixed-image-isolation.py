#!/usr/bin/env python3
"""iDeck-BCD, 2026-10-22: run the production fixed-image window registry.

The host harness checks private data at equal guest addresses, exact ownership,
span boundaries, refusal/rollback, capacity, teardown/reuse and concurrent
publication. It is not a Wine/FEX/device execution test. --static-only avoids
compilation; --pe-dir additionally validates the two device regression PEs.
"""
from pathlib import Path
import argparse
import os
import re
import struct
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]


def check_pe(path):
    data = path.read_bytes()
    assert data[:2] == b'MZ', (path, 'DOS signature')
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    assert data[pe:pe + 4] == b'PE\0\0', (path, 'PE signature')
    machine, nsec, _, symbols_at, nsymbols, optional_size, flags = struct.unpack_from('<HHIIIHH', data, pe + 4)
    optional = pe + 24
    assert machine == 0x8664 and struct.unpack_from('<H', data, optional)[0] == 0x20b, (path, 'x64 PE32+')
    assert flags & 1, (path, 'IMAGE_FILE_RELOCS_STRIPPED missing')
    assert struct.unpack_from('<Q', data, optional + 24)[0] == 0x140000000, (path, 'fixed image base')
    assert not struct.unpack_from('<H', data, optional + 70)[0] & 0x40, (path, 'DYNAMIC_BASE enabled')
    assert struct.unpack_from('<II', data, optional + 112 + 5 * 8) == (0, 0), (path, 'base relocations present')
    sections = []
    for i in range(nsec):
        at = optional + optional_size + i * 40
        _, rva, raw_size, raw_at = struct.unpack_from('<IIII', data, at + 8)
        sections.append((rva, raw_at, raw_size))
    strings_at = symbols_at + nsymbols * 18
    symbols = {}
    i = 0
    while i < nsymbols:
        at = symbols_at + i * 18
        name = data[at:at + 8]
        if name[:4] == bytes(4):
            name_at = strings_at + struct.unpack_from('<I', name, 4)[0]
            name = data[name_at:data.index(b'\0', name_at)]
        else:
            name = name.split(b'\0', 1)[0]
        value, section = struct.unpack_from('<Ih', data, at + 8)
        if 0 < section <= nsec:
            rva, raw_at, raw_size = sections[section - 1]
            symbols[name.decode('ascii', errors='replace')] = (rva + value, data[raw_at + value:raw_at + min(value + 16, raw_size)])
        i += 1 + data[at + 17]
    assert 'fixed_code_identity' in symbols, (path, 'code identity symbol missing')
    return symbols


def check_pes(directory):
    parent = check_pe(directory / 'fixed-parent.exe')
    child = check_pe(directory / 'fixed-child.exe')
    for name in ('fixed_code_identity', 'cookie', 'cookie_pointer', 'role', 'code_pointer'):
        assert name in parent and name in child, ('missing fixture symbol', name)
        assert parent[name][0] == child[name][0], ('fixture guest addresses differ', name)
    assert parent['fixed_code_identity'][1] != child['fixed_code_identity'][1], 'same guest RIP must execute different instructions'
    assert parent['role'][1] != child['role'][1], 'private image data must differ at the same guest address'
    print('PASS: two x64 PEs at 0x140000000, stripped relocations, equal symbol addresses, different code/data')


def function(source, signature):
    # These sources put the function's closing brace alone in column zero;
    # an in-function macro can also start with `}`, followed by `while (0)`.
    start = re.search(re.escape(signature) + r'[^;{}]*\n\{', source).start()
    end = re.search(r'^}$', source[start:], re.MULTILINE).end()
    return source[start:start + end] + '\n'


def reservation_harness(source):
    helpers = function(source, 'static int ios_fixed_image_isolation(void)')
    helpers += function(source, 'static BOOL ios_fixed_image_candidate(')
    helpers += function(source, 'static BOOL ios_fixed_image_fits(')
    start = source.index('static struct { ULONG_PTR base; SIZE_T size; } ios_fixed_guards[')
    end = source.index('static NTSTATUS ios_fixed_image_reserve(', start)
    helpers += source[start:end] + function(source, 'static NTSTATUS ios_fixed_image_reserve(')
    return r'''
typedef uintptr_t ULONG_PTR;
typedef size_t SIZE_T;
typedef unsigned NTSTATUS;
typedef int BOOL;
typedef uint64_t mach_vm_address_t;
typedef int kern_return_t;
#define STATUS_SUCCESS 0
#define STATUS_INVALID_PARAMETER 1
#define STATUS_CONFLICTING_ADDRESSES 2
#define STATUS_NO_MEMORY 3
#define KERN_SUCCESS 0
#define VM_FLAGS_FIXED 0
#define MEMORY_OBJECT_NULL 0
#define VM_PROT_NONE 0
#define VM_INHERIT_NONE 0
#define TRUE 1
#define FALSE 0
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define IMAGE_FILE_MACHINE_AMD64 0x8664
#define IMAGE_FILE_RELOCS_STRIPPED 1
struct pe_image_info {
    int wine_builtin, is_hybrid;
    uint64_t map_addr, base;
    unsigned machine, image_charact;
};
static int per_process = 1, ios_exe_win_resource_request;
static int ios_alias_per_process_enabled(void) { return per_process; }
static ULONG_PTR host_page_mask = 0x3fff;
static int ios_exe_win_state;
static uint64_t ios_exe_win_base, ios_exe_win_size;
static unsigned maps;
static uint64_t mapped_at, mapped_size;
static int live_view, map_error;
struct reserved_area { void *base; SIZE_T size; };
static struct reserved_area reserved_areas[3];
static unsigned reserved_count;
#define LIST_FOR_EACH_ENTRY(cursor, list, type, member) \
    for ((cursor) = reserved_areas; (cursor) < reserved_areas + reserved_count; ++(cursor))
static int protect_error;
static unsigned protects;
static uint64_t protected_at, protected_size;
static void *find_view_range(void *base, size_t size)
{ (void)base; return live_view == 1 || (live_view == 2 && size == ios_exe_win_size) ? (void *)1 : NULL; }
static void ios_exe_win_init(void) { ios_exe_win_state = 0; }
static unsigned mach_task_self(void) { return 1; }
static int mach_vm_protect(unsigned task, mach_vm_address_t at, size_t size,
                           int maximum, unsigned prot)
{
    assert(task == 1 && maximum == TRUE && prot == VM_PROT_NONE);
    protects++; protected_at = at; protected_size = size;
    return protect_error;
}
static int mach_vm_map(unsigned task, mach_vm_address_t *at, size_t size, unsigned mask,
                       unsigned flags, unsigned object, unsigned offset, int copy,
                       unsigned prot, unsigned maxprot, unsigned inheritance)
{
    assert(task == 1 && mask == 0 && flags == VM_FLAGS_FIXED);
    assert(!object && !offset && !copy && prot == VM_PROT_NONE && maxprot == VM_PROT_NONE);
    assert(inheritance == VM_INHERIT_NONE);
    maps++; mapped_at = *at; mapped_size = size;
    return map_error;
}
''' + helpers + r'''
static void reservations(void)
{
    struct pe_image_info info = { .base = 0x140000000ULL, .machine = IMAGE_FILE_MACHINE_AMD64,
                                  .image_charact = IMAGE_FILE_RELOCS_STRIPPED };
    assert(ios_fixed_image_fits(0x140000000ULL, 0x4000, 0x140000000ULL, 0x140003fffULL));
    assert(ios_fixed_image_fits(0x140000001ULL, 0x3fff, 0x140000000ULL, 0x140003fffULL));
    assert(!ios_fixed_image_fits(0x13fffffffULL, 1, 0x140000000ULL, 0x140003fffULL));
    assert(!ios_fixed_image_fits(0x140004000ULL, 1, 0x140000000ULL, 0x140003fffULL));
    assert(!ios_fixed_image_fits(0x140000000ULL, 0x4001, 0x140000000ULL, 0x140003fffULL));
    assert(!ios_fixed_image_fits(0x140000000ULL, 0, 0x140000000ULL, 0x140003fffULL));
    assert(!ios_fixed_image_fits(0x140000000ULL, SIZE_MAX, 0, UINTPTR_MAX));
    assert(!ios_fixed_image_fits(UINTPTR_MAX - 15, 32, 0, UINTPTR_MAX));
    assert(ios_fixed_image_fits(UINTPTR_MAX, 1, 0, UINTPTR_MAX));
    assert(!ios_fixed_image_fits(UINTPTR_MAX, 2, 0, UINTPTR_MAX));
    assert(!ios_fixed_image_fits(0x140000000ULL, 1, 0x140000001ULL, 0x140000000ULL));
    unsetenv("MADEIRA_FIXED_IMAGE_ISOLATION");
    assert(!ios_fixed_image_isolation() && !ios_fixed_image_candidate(&info));
    const char *disabled[] = { "", "0", "true", "11", "1 " };
    for (unsigned i = 0; i < ARRAY_SIZE(disabled); ++i)
    {
        setenv("MADEIRA_FIXED_IMAGE_ISOLATION", disabled[i], 1);
        assert(!ios_fixed_image_isolation() && !ios_fixed_image_candidate(&info));
    }
    setenv("MADEIRA_FIXED_IMAGE_ISOLATION", "1", 1);
    assert(ios_fixed_image_isolation() && ios_fixed_image_candidate(&info));
    per_process = 0; assert(!ios_fixed_image_candidate(&info)); per_process = 1;
    ios_exe_win_resource_request = 1; assert(!ios_fixed_image_candidate(&info)); ios_exe_win_resource_request = 0;
    info.wine_builtin = 1; assert(!ios_fixed_image_candidate(&info)); info.wine_builtin = 0;
    info.is_hybrid = 1; assert(!ios_fixed_image_candidate(&info)); info.is_hybrid = 0;
    info.map_addr = 0x140000000; assert(!ios_fixed_image_candidate(&info)); info.map_addr = 0;
    info.base = 0x400000; assert(!ios_fixed_image_candidate(&info)); info.base = 0x140000000;
    info.machine = 0xaa64; assert(!ios_fixed_image_candidate(&info)); info.machine = IMAGE_FILE_MACHINE_AMD64;
    info.image_charact = 0; assert(!ios_fixed_image_candidate(&info)); info.image_charact = IMAGE_FILE_RELOCS_STRIPPED;

    ios_exe_win_state = 1;
    ios_exe_win_base = 0x140000000ULL; ios_exe_win_size = 0x8000000;
    const struct reserved_area conflicts[] = {
        {(void *)0x140000000ULL, 0x8000000}, /* fully contained */
        {(void *)0x13fffc000ULL, 0x5000},   /* overlap at beginning */
        {(void *)0x140002000ULL, 0x1000},   /* reserved interval starts inside request */
        {(void *)0x140008000ULL, 0x1000}    /* only expanded startup window overlaps */
    };
    reserved_count = 1;
    for (unsigned i = 0; i < ARRAY_SIZE(conflicts); ++i)
    {
        reserved_areas[0] = conflicts[i];
        assert(ios_fixed_image_reserve(0x140000000ULL, 1) == STATUS_CONFLICTING_ADDRESSES);
        assert(!ios_fixed_guard_count && !protects && !maps);
    }
    reserved_areas[0] = (struct reserved_area){(void *)0x13fffc000ULL, 0x4000};
    reserved_areas[1] = (struct reserved_area){(void *)0x148000000ULL, 0x4000};
    reserved_count = 2;
    assert(!ios_fixed_reserved_overlap(0x140000000ULL, 0x8000000));
    reserved_count = 0;
    protect_error = 7;
    assert(ios_fixed_image_reserve(0x140000000ULL, 1) == STATUS_CONFLICTING_ADDRESSES);
    assert(!ios_fixed_guard_count && protects == 1 && !maps);
    protect_error = 0; live_view = 2;
    assert(ios_fixed_image_reserve(0x140000000ULL, 1) == STATUS_CONFLICTING_ADDRESSES);
    assert(!ios_fixed_guard_count && protects == 1 && !maps);
    live_view = 0;
    assert(ios_fixed_image_reserve(0x140000000ULL, 1) == STATUS_SUCCESS);
    assert(!maps && ios_fixed_guard_count == 1 && ios_fixed_guards[0].size == 0x8000000);
    assert(protects == 2 && protected_at == 0x140000000ULL && protected_size == 0x8000000);
    assert(ios_fixed_image_reserve(0x140004000ULL, 0x7ffc000) == STATUS_SUCCESS && !maps);
    assert(ios_fixed_image_reserve(0x13fffc000ULL, 0x8000) == STATUS_CONFLICTING_ADDRESSES && !maps);
    assert(ios_fixed_image_reserve(0x240000000ULL, 0x4001) == STATUS_SUCCESS);
    assert(maps == 1 && mapped_at == 0x240000000ULL && mapped_size == 0x8000);
    assert(ios_fixed_image_reserve(0x240000000ULL, 0x8000) == STATUS_SUCCESS && maps == 1);
    assert(ios_fixed_image_reserve(0x240004000ULL, 0x8000) == STATUS_CONFLICTING_ADDRESSES && maps == 1);
    assert(ios_fixed_image_reserve(0x400000, 64) == STATUS_INVALID_PARAMETER);
    assert(ios_fixed_image_reserve(0x340000001ULL, 64) == STATUS_INVALID_PARAMETER);
    assert(ios_fixed_image_reserve(0x340000000ULL, 0) == STATUS_INVALID_PARAMETER);
    assert(ios_fixed_image_reserve(0x340000000ULL, SIZE_MAX) == STATUS_INVALID_PARAMETER);
    assert(ios_fixed_image_reserve(0x8000000000000000ULL, 64) == STATUS_INVALID_PARAMETER);
    ios_exe_win_base = (1ULL << 47) - 0x10000; ios_exe_win_size = 0x20000;
    assert(ios_fixed_image_reserve(ios_exe_win_base, 64) == STATUS_CONFLICTING_ADDRESSES);
    assert(ios_fixed_guard_count == 2 && protects == 2);
    ios_exe_win_base = 0x140000000ULL; ios_exe_win_size = 0x8000000;
    live_view = 1;
    assert(ios_fixed_image_reserve(0x340000000ULL, 64) == STATUS_CONFLICTING_ADDRESSES && maps == 1);
    live_view = 0; map_error = 5;
    assert(ios_fixed_image_reserve(0x340000000ULL, 64) == STATUS_CONFLICTING_ADDRESSES);
    assert(ios_fixed_guard_count == 2);
    map_error = 0;
    for (unsigned i = 2; i < ARRAY_SIZE(ios_fixed_guards); ++i)
        assert(ios_fixed_image_reserve(0x440000000ULL + i * 0x10000, 64) == STATUS_SUCCESS);
    assert(ios_fixed_image_reserve(0x540000000ULL, 64) == STATUS_NO_MEMORY);
    puts("PASS: strict default-off selection; PROT_NONE no-overwrite reservation, startup reuse, bounds/capacity/failure");
}
'''


def ordered_harness(source):
    helper = function(source, 'static int ios_emulate_fixed_ordered(').replace('ucontext_t', 'fixed_test_context')
    assert '#undef IOS_FIXED_ATOMIC' in helper and helper.endswith('    return 1;\n}\n')
    return r'''
typedef struct { uint64_t regs[32]; } fixed_test_context;
static uint64_t ios_get_reg(fixed_test_context *ctx, int r) { return r == 31 ? 0 : ctx->regs[r]; }
static void ios_ld_setreg(fixed_test_context *ctx, int r, uint64_t value) { if (r != 31) ctx->regs[r] = value; }
''' + helper + r'''
static _Alignas(16) uint64_t atomic_words[2];
static void *trapped_adds(void *unused)
{
    fixed_test_context ctx = {{0}};
    (void)unused;
    ctx.regs[1] = 1;
    for (int i = 0; i < 20000; ++i)
        assert(ios_emulate_fixed_ordered(&ctx, 0xf8e10002, (uintptr_t)atomic_words) == 1);
    return NULL;
}
static void ordered_atomics(void)
{
    static const unsigned operations[] = {0x0000, 0x1000, 0x2000, 0x3000, 0x8000};
    fixed_test_context ctx = {{0}};
    pthread_t worker;
    for (unsigned size = 0; size < 4; ++size)
    {
        unsigned bytes = 1u << size;
        uint64_t mask = bytes == 8 ? UINT64_MAX : (1ULL << (bytes * 8)) - 1;
        for (unsigned op = 0; op < ARRAY_SIZE(operations); ++op)
        {
            uint64_t expected, after = 0;
            atomic_words[0] = 0x35;
            ctx.regs[1] = 0x12; ctx.regs[2] = UINT64_MAX;
            uint32_t instruction = 0x38e10002 | (size << 30) | operations[op];
            expected = op == 0 ? 0x47 : op == 1 ? (0x35 & ~0x12) :
                       op == 2 ? (0x35 ^ 0x12) : op == 3 ? (0x35 | 0x12) : 0x12;
            assert(ios_emulate_fixed_ordered(&ctx, instruction, (uintptr_t)atomic_words) == 1);
            memcpy(&after, atomic_words, bytes);
            assert(ctx.regs[2] == 0x35 && after == (expected & mask));
            if (bytes > 1)
            {
                uint64_t before = atomic_words[0];
                assert(ios_emulate_fixed_ordered(&ctx, instruction, (uintptr_t)atomic_words + 1) == -1);
                assert(before == atomic_words[0]);
            }
        }
        atomic_words[0] = 0;
        ctx.regs[2] = 0x123456789abcdef0ULL;
        assert(ios_emulate_fixed_ordered(&ctx, 0x089ffc02 | (size << 30), (uintptr_t)atomic_words) == 1);
        assert(ios_emulate_fixed_ordered(&ctx, 0x08dffc02 | (size << 30), (uintptr_t)atomic_words) == 1);
        assert(ctx.regs[2] == (0x123456789abcdef0ULL & mask));
    }
    atomic_words[0] = 0x80;
    assert(ios_emulate_fixed_ordered(&ctx, 0x19800002, (uintptr_t)atomic_words) == 1);
    assert(ctx.regs[2] == (uint64_t)(int64_t)-128);
    assert(ios_emulate_fixed_ordered(&ctx, 0x19c00002, (uintptr_t)atomic_words) == 1);
    assert(ctx.regs[2] == 0xffffff80);
    uint64_t before = atomic_words[0];
    for (unsigned op = 0; op < 4; ++op)
    {
        const uint32_t exclusive[] = {0xc85ffc02, 0xc85f7c02, 0xc801fc02, 0xc8017c02};
        assert(ios_emulate_fixed_ordered(&ctx, exclusive[op], (uintptr_t)atomic_words) == -1);
        assert(atomic_words[0] == before);
    }
    assert(ios_emulate_fixed_ordered(&ctx, 0xc8a07c02, (uintptr_t)atomic_words) == 0);
    assert(ios_emulate_fixed_ordered(&ctx, 0x48207c02, (uintptr_t)atomic_words) == 0);
    assert(ios_emulate_fixed_ordered(&ctx, 0x48207c03, (uintptr_t)atomic_words) == -1);
    assert(ios_emulate_fixed_ordered(&ctx, 0x48207c02, (uintptr_t)atomic_words + 8) == -1);
    assert(ios_emulate_fixed_ordered(&ctx, 0xb9400002, (uintptr_t)atomic_words) == 0);
    atomic_words[0] = 0;
    assert(!pthread_create(&worker, NULL, trapped_adds, NULL));
    for (int i = 0; i < 20000; ++i) __atomic_fetch_add(atomic_words, 1, __ATOMIC_SEQ_CST);
    assert(!pthread_join(worker, NULL));
    assert(atomic_words[0] == 40000);
    puts("PASS: production ordered/LSE operations preserve widths and old values; contended native updates are not lost");
}
'''


def harness(source, virtual, mach):
    start = source.index('#define IOS_SUBFLOOR_MAX ')
    end = source.index('/* Read `size` bytes at `a`', start)
    production = source[start:end]
    return r'''
#define _GNU_SOURCE
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#define IOS_FIXED_IMAGE_IO_IMPL 1
#include "shims/ios_fixed_image_io.h"
static unsigned pushes;
static unsigned long long last_guest, last_real, last_size;
static void *last_owner;
static int quiet_dprintf(int fd, const char *fmt, ...) { (void)fd; (void)fmt; return 0; }
#define dprintf quiet_dprintf
void ios_push_subfloor_window(unsigned long long guest, unsigned long long real,
                             unsigned long long size, void *owner)
{
    pushes++;
    last_guest = guest; last_real = real; last_size = size; last_owner = owner;
}
''' + reservation_harness(virtual) + ordered_harness(source) + production + r'''
typedef uint64_t client_ptr_t;
typedef size_t data_size_t;
struct process { int unix_pid; client_ptr_t peb; };
''' + function(mach, 'static int ios_target_fixed_image(') + r'''
#define GUEST 0x140000000ULL
static char owner_a, owner_b, owner_c;
#define A (&owner_a)
#define B (&owner_b)
#define C (&owner_c)
static void *current_owner;
void *ios_jit_current_peb(void) { return current_owner; }
static unsigned char bytes_a[64], bytes_b[64], bytes_c[64];
#define REAL(p) ((unsigned long long)(uintptr_t)(p))
static void reset(void)
{
    memset(ios_subfloor, 0, sizeof(ios_subfloor));
    ios_subfloor_count = 0;
    __atomic_store_n(&ios_fixed_image_ever_registered, 0, __ATOMIC_RELEASE);
    pushes = 0;
}
static void boundaries(void)
{
    unsigned long long real = 0;
    reset();
    memset(bytes_a, 0xa1, sizeof(bytes_a));
    memset(bytes_b, 0xb2, sizeof(bytes_b));
    assert(ios_register_fixed_image_window(GUEST, sizeof(bytes_a), REAL(bytes_a), A));
    assert(ios_register_fixed_image_window(GUEST, sizeof(bytes_b), REAL(bytes_b), B));
    assert(ios_fixed_image_guarded(GUEST) && ios_fixed_image_guarded(GUEST + 63));
    assert(!ios_fixed_image_guarded(GUEST - 1) && !ios_fixed_image_guarded(GUEST + 64));
    assert(!ios_fixed_image_guarded(0x400000));
    assert(pushes == 2 && last_guest == GUEST && last_owner == B && last_real == REAL(bytes_b));
    assert(ios_fixed_image_translate(GUEST, 64, A, &real) && real == REAL(bytes_a));
    memset((void *)(uintptr_t)real, 0xa3, 64);
    assert(ios_fixed_image_translate(GUEST, 64, B, &real) && real == REAL(bytes_b));
    assert(*(unsigned char *)(uintptr_t)real == 0xb2 && bytes_a[0] == 0xa3);
    struct process target = {getpid(), (client_ptr_t)(uintptr_t)B};
    client_ptr_t target_real;
    current_owner = A;
    assert(ios_target_fixed_image(&target, GUEST, 64, &target_real) && target_real == REAL(bytes_b));
    target.peb = 0;
    assert(!ios_target_fixed_image(&target, GUEST, 1, &target_real));
    target.peb = (client_ptr_t)(uintptr_t)B; target.unix_pid++;
    assert(!ios_target_fixed_image(&target, GUEST, 1, &target_real));
    assert(ios_fixed_image_translate(GUEST + 63, 1, A, &real) && real == REAL(bytes_a + 63));
    assert(ios_fixed_image_translate(GUEST, 0, A, &real) && real == REAL(bytes_a));
    real = 0xdeadbeef;
    assert(!ios_fixed_image_translate(GUEST, 1, NULL, &real) && real == 0xdeadbeef);
    assert(!ios_fixed_image_translate(GUEST, 1, C, &real));
    assert(!ios_fixed_image_translate(GUEST - 1, 1, A, &real));
    assert(!ios_fixed_image_translate(GUEST + 64, 1, A, &real));
    assert(!ios_fixed_image_translate(GUEST + 63, 2, A, &real));
    assert(!ios_fixed_image_translate(GUEST, 65, A, &real));
    assert(!ios_fixed_image_translate(UINT64_MAX - 1, 8, A, &real));
    assert(!ios_fixed_image_translate(0x400000, 1, A, &real));
    assert(!ios_register_fixed_image_window(GUEST, 0, REAL(bytes_a), A));
    assert(!ios_register_fixed_image_window(GUEST, 64, REAL(bytes_a), NULL));
    assert(!ios_register_fixed_image_window(0x400000, 64, REAL(bytes_a), A));
    assert(!ios_register_fixed_image_window(UINT64_MAX - 1, 64, REAL(bytes_a), A));
    assert(!ios_register_fixed_image_window(GUEST, 64, UINT64_MAX - 1, A));
    assert(!ios_register_fixed_image_window(GUEST, 64, GUEST + 1, A));
    assert(!ios_register_fixed_image_window(GUEST, 64, REAL(bytes_c), A));
    assert(!ios_register_fixed_image_window(GUEST + 32, 64, REAL(bytes_c), A));
    assert(ios_register_fixed_image_window(GUEST, 64, REAL(bytes_a), A));
    assert(!ios_unregister_fixed_image_window(GUEST, REAL(bytes_c), A));
    assert(ios_fixed_image_translate(GUEST, 64, A, &real) && real == REAL(bytes_a));
    assert(ios_unregister_fixed_image_window(GUEST, REAL(bytes_a), A));
    assert(last_guest == GUEST && last_real == REAL(bytes_a) && last_size == 0 && last_owner == A);
    assert(!ios_fixed_image_translate(GUEST, 1, A, &real));
    assert(ios_fixed_image_translate(GUEST, 64, B, &real) && real == REAL(bytes_b));
    assert(ios_register_fixed_image_window(GUEST, 64, REAL(bytes_c), A));
    assert(!ios_unregister_fixed_image_window(GUEST, REAL(bytes_a), A));
    assert(ios_fixed_image_translate(GUEST, 64, A, &real) && real == REAL(bytes_c));
    ios_subfloor_release_owner(A);
    assert(!ios_fixed_image_translate(GUEST, 1, A, &real));
    assert(ios_fixed_image_guarded(GUEST)); /* another owner still guards this VA */
    assert(ios_fixed_image_translate(GUEST, 64, B, &real) && real == REAL(bytes_b));
    ios_subfloor_release_owner(NULL);
    assert(ios_fixed_image_translate(GUEST, 64, B, &real));
    ios_subfloor_release_owner(B);
    assert(!ios_fixed_image_translate(GUEST, 1, B, &real));
    assert(!ios_fixed_image_guarded(GUEST));
    puts("PASS: equal guest addresses use private data; full spans, invalid owners/ranges, rollback, teardown and reuse");
}
static void legacy_and_capacity(void)
{
    unsigned long long low, real, size;
    void *owner;
    reset();
    ios_register_subfloor_image(0x400000, 64, REAL(bytes_a), A);
    ios_register_subfloor_image(0x400000, 64, REAL(bytes_b), B);
    ios_register_subfloor_image(0x7ffe0000, 64, REAL(bytes_c), NULL);
    assert(ios_subfloor_translate(0x400000, A) == (uintptr_t)bytes_a);
    assert(ios_subfloor_translate(0x400000, B) == (uintptr_t)bytes_b);
    assert(ios_subfloor_translate(0x400000, NULL));
    assert(ios_subfloor_translate(0x7ffe0000, A) == (uintptr_t)bytes_c);
    assert(ios_subfloor_translate(0x7ffe0000, B) == (uintptr_t)bytes_c);
    assert(ios_subfloor_enum(0, &low, &real, &size, &owner));
    assert(low == 0x400000 && real == REAL(bytes_a) && size == 64 && owner == A);
    assert(!ios_subfloor_enum(-1, &low, &real, &size, &owner));
    assert(!ios_subfloor_enum(ios_subfloor_count, &low, &real, &size, &owner));
    reset();
    for (int i = 0; i < IOS_SUBFLOOR_MAX; ++i)
        assert(ios_register_fixed_image_window(GUEST + i * 0x1000ULL, 64, REAL(bytes_a), A));
    unsigned before = pushes;
    assert(!ios_register_fixed_image_window(GUEST + IOS_SUBFLOOR_MAX * 0x1000ULL, 64, REAL(bytes_b), B));
    assert(pushes == before);
    ios_subfloor_release_owner(A);
    for (int i = 0; i < IOS_SUBFLOOR_MAX; ++i)
        assert(ios_register_fixed_image_window(GUEST + i * 0x1000ULL, 64, REAL(bytes_b), B));
    assert(ios_subfloor_count == IOS_SUBFLOOR_MAX);
    puts("PASS: legacy low/shared windows preserved; full table refuses publication and retired slots are reusable");
}
static void *replace_window(void *unused)
{
    (void)unused;
    for (int i = 0; i < 10000; ++i)
    {
        unsigned char *old = i & 1 ? bytes_c : bytes_a;
        unsigned char *next = i & 1 ? bytes_a : bytes_c;
        assert(ios_unregister_fixed_image_window(GUEST, REAL(old), A));
        assert(ios_register_fixed_image_window(GUEST, 64, REAL(next), A));
    }
    return NULL;
}
static void concurrency(void)
{
    pthread_t writer;
    reset();
    assert(ios_register_fixed_image_window(GUEST, 64, REAL(bytes_a), A));
    assert(ios_register_fixed_image_window(GUEST, 64, REAL(bytes_b), B));
    assert(!pthread_create(&writer, NULL, replace_window, NULL));
    for (int i = 0; i < 50000; ++i)
    {
        unsigned long long real;
        if (ios_fixed_image_translate(GUEST + 63, 1, A, &real))
            assert(real == REAL(bytes_a + 63) || real == REAL(bytes_c + 63));
        assert(ios_fixed_image_translate(GUEST + 63, 1, B, &real) && real == REAL(bytes_b + 63));
        assert(!ios_fixed_image_translate(GUEST, 1, C, &real));
    }
    assert(!pthread_join(writer, NULL));
    puts("PASS: concurrent retirement/publication never returns a foreign owner's backing");
}
static void native_io(void)
{
    struct io_image {
        char source[16], target[32];
        struct iovec iov[2];
        struct msghdr message;
        struct sockaddr_storage address;
        socklen_t address_length;
        int option;
        socklen_t option_length;
        unsigned char control[128];
    } parent = {0}, child = {0};
    const uintptr_t guest = 0x141000000ULL;
#define FIELD(member) ((void *)(guest + offsetof(struct io_image, member)))
    int pipefd[2], sockets[2];
    char readback[32] = {0}, native_part[8] = {0};
    struct iovec saved_iov[2];
    char filename[] = "/tmp/ideck-fixed-io-XXXXXX";
    int file;

    reset();
    current_owner = A;
    assert(!pipe(pipefd));
    /* Before the feature has ever been used, ordinary buffers go unchanged. */
    assert(!ios_fixed_image_io_active());
    assert(ios_fixed_write(pipefd[1], "plain", 5) == 5);
    assert(ios_fixed_read(pipefd[0], readback, 5) == 5 && !memcmp(readback, "plain", 5));
    strcpy(parent.source, "parent"); strcpy(child.source, "child!");
    assert(ios_register_fixed_image_window(guest, sizeof(parent), REAL(&parent), A));
    assert(ios_register_fixed_image_window(guest, sizeof(child), REAL(&child), B));
    assert(ios_fixed_image_io_active());
    assert(ios_fixed_write(pipefd[1], FIELD(source), 6) == 6);
    assert(read(pipefd[0], readback, 6) == 6 && !memcmp(readback, "parent", 6));
    current_owner = B;
    assert(ios_fixed_write(pipefd[1], FIELD(source), 6) == 6);
    assert(read(pipefd[0], readback, 6) == 6 && !memcmp(readback, "child!", 6));
    assert(write(pipefd[1], "private", 7) == 7);
    assert(ios_fixed_read(pipefd[0], FIELD(target), 7) == 7);
    assert(!memcmp(child.target, "private", 7) && !parent.target[0]);
    current_owner = A;
    parent.iov[0] = (struct iovec){FIELD(source), 6};
    parent.iov[1] = (struct iovec){(void *)"-native", 7};
    memcpy(saved_iov, parent.iov, sizeof(saved_iov));
    assert(ios_fixed_writev(pipefd[1], FIELD(iov), 2) == 13);
    assert(read(pipefd[0], readback, 13) == 13 && !memcmp(readback, "parent-native", 13));
    assert(!memcmp(saved_iov, parent.iov, sizeof(saved_iov)));
    parent.iov[0] = (struct iovec){FIELD(target), 4};
    parent.iov[1] = (struct iovec){native_part, 3};
    memcpy(saved_iov, parent.iov, sizeof(saved_iov));
    assert(write(pipefd[1], "abcdXYZ", 7) == 7);
    assert(ios_fixed_readv(pipefd[0], FIELD(iov), 2) == 7);
    assert(!memcmp(parent.target, "abcd", 4) && !memcmp(native_part, "XYZ", 3));
    assert(!memcmp(saved_iov, parent.iov, sizeof(saved_iov)));
    errno = 0;
    ssize_t empty_result = writev(pipefd[1], NULL, 0);
    int empty_errno = errno;
    errno = 0;
    assert(ios_fixed_writev(pipefd[1], NULL, 0) == empty_result && errno == empty_errno);
    errno = 0;
    assert(ios_fixed_writev(-1, FIELD(iov), 2) == -1 && errno == EBADF);
    errno = 0;
    assert(ios_fixed_read(-1, FIELD(target), 1) == -1 && errno == EBADF);
    close(pipefd[0]); close(pipefd[1]);

    file = mkstemp(filename);
    assert(file >= 0 && !unlink(filename));
    assert(ios_fixed_pwrite(file, FIELD(source), 6, 3) == 6);
    memset(parent.target, 0, sizeof(parent.target));
    assert(ios_fixed_pread(file, FIELD(target), 6, 3) == 6);
    assert(!memcmp(parent.target, "parent", 6));
    close(file);

    assert(!socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets));
    parent.option_length = sizeof(parent.option);
    assert(!ios_fixed_getsockopt(sockets[0], SOL_SOCKET, SO_TYPE, FIELD(option), FIELD(option_length)));
    assert(parent.option == SOCK_DGRAM && parent.option_length == sizeof(parent.option));
    parent.option = 8192;
    assert(!ios_fixed_setsockopt(sockets[0], SOL_SOCKET, SO_RCVBUF, FIELD(option), sizeof(parent.option)));
    assert(parent.option == 8192);
    parent.iov[0] = (struct iovec){FIELD(source), 6};
    parent.message.msg_iov = FIELD(iov); parent.message.msg_iovlen = 1;
    memcpy(saved_iov, parent.iov, sizeof(saved_iov));
    assert(ios_fixed_sendmsg(sockets[0], FIELD(message), 0) == 6);
    assert(recv(sockets[1], readback, sizeof(readback), 0) == 6 && !memcmp(readback, "parent", 6));
    assert(parent.message.msg_iov == FIELD(iov) && !memcmp(saved_iov, parent.iov, sizeof(saved_iov)));
    parent.iov[0] = (struct iovec){FIELD(target), sizeof(parent.target)};
    parent.message.msg_name = FIELD(address);
    parent.message.msg_namelen = sizeof(parent.address);
    parent.message.msg_control = FIELD(control);
    parent.message.msg_controllen = sizeof(parent.control);
    parent.message.msg_flags = -1;
    memcpy(saved_iov, parent.iov, sizeof(saved_iov));
    assert(send(sockets[1], "reply", 5, 0) == 5);
    assert(ios_fixed_recvmsg(sockets[0], FIELD(message), 0) == 5);
    assert(!memcmp(parent.target, "reply", 5));
    assert(!parent.message.msg_controllen && !parent.message.msg_flags);
    assert(parent.message.msg_namelen <= sizeof(parent.address));
    assert(parent.message.msg_iov == FIELD(iov) && !memcmp(saved_iov, parent.iov, sizeof(saved_iov)));
    assert(ios_fixed_sendto(sockets[0], FIELD(source), 6, 0, NULL, 0) == 6);
    assert(recv(sockets[1], readback, sizeof(readback), 0) == 6 && !memcmp(readback, "parent", 6));
    assert(ios_fixed_send(sockets[0], FIELD(source), 6, 0) == 6);
    assert(ios_fixed_recv(sockets[1], FIELD(target), sizeof(parent.target), 0) == 6);
    assert(!memcmp(parent.target, "parent", 6));
    assert(send(sockets[1], "from", 4, 0) == 4);
    parent.address_length = sizeof(parent.address);
    assert(ios_fixed_recvfrom(sockets[0], FIELD(target), sizeof(parent.target), 0,
                              FIELD(address), FIELD(address_length)) == 4);
    assert(!memcmp(parent.target, "from", 4) && parent.address_length <= sizeof(parent.address));
    close(sockets[0]); close(sockets[1]);
    ios_subfloor_release_owner(A); ios_subfloor_release_owner(B);
    puts("PASS: production POSIX wrappers preserve owner buffers, native pointers, vectors, message metadata and syscall errno");
#undef FIELD
}
int main(void)
{
    native_io(); reservations(); ordered_atomics(); boundaries(); legacy_and_capacity(); concurrency();
    return 0;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--static-only', action='store_true')
    parser.add_argument('--pe-dir', type=Path)
    args = parser.parse_args()
    source = (ROOT / 'build/ntdll-unix/signal_arm64_ios.c').read_text()
    virtual = (ROOT / 'build/ntdll-unix/virtual_ios.c').read_text()
    code = harness(source, virtual,
                   (ROOT / 'build/wineserver/mach_ios.c').read_text())
    mapping = function(virtual, 'static NTSTATUS map_image_view(')
    start = mapping.index('if (!is_builtin && !wow_image && ios_fixed_image_candidate( image_info ))')
    isolated = mapping[start:mapping.index('\n    }', start)]
    assert isolated.index('ios_fixed_image_fits( image_info->base, size, limit_low, limit_high )') \
        < isolated.index('ios_fixed_image_reserve( image_info->base, size )') < isolated.index('return map_view(')
    assert re.search(r'return map_view\( view_ret, NULL, size, MEM_TOP_DOWN, vprot,\s*'
                     r'\(ULONG_PTR\)limit_4g, 0, 0 \);', isolated), 'backing must not inherit guest address bounds'
    server = (ROOT / 'build/ntdll-unix/server_ios.c').read_text()
    assert 'ios_subfloor_release_owner( dead_peb );' in server, 'exit must retire the process windows'
    for name in ('ios_register_fixed_image_window', 'ios_unregister_fixed_image_window', 'ios_fixed_image_translate'):
        assert name in code, name
    if args.pe_dir:
        check_pes(args.pe_dir)
    if args.static_only:
        print('PASS: fixed-image helper extraction and exit wiring; native execution NOT RUN (--static-only)')
        return
    with tempfile.TemporaryDirectory(prefix='ideck-fixed-image-') as directory:
        folder = Path(directory)
        c_file = folder / 'check.c'
        executable = folder / 'check'
        c_file.write_text(code)
        subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                        '-Wno-unused-variable', '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                        '-pthread', '-I', str(ROOT / 'build/ntdll-unix'), str(c_file),
                        str(ROOT / 'build/ntdll-unix/ios_fixed_image_io.c'), '-o', str(executable)], check=True)
        subprocess.run([str(executable)], check=True)
        exclusive = folder / 'exclusive'
        (folder / 'fixed-service.inc').write_text(function(source, 'static int ios_service_fixed_exclusive('))
        subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                        '-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-pthread',
                        '-I', str(ROOT / 'build/ntdll-unix'), '-I', str(folder),
                        str(ROOT / 'tests/host/fixed_exclusive.c'),
                        '-o', str(exclusive)], check=True)
        subprocess.run([str(exclusive)], check=True)
        abi = folder / 'abi'
        (folder / 'fixed-abi.inc').write_text(''.join(function(virtual, signature) for signature in (
            'static int ios_safe_read(', 'static int ios_fixed_pe_read(',
            'static int ios_fixed_pe_abi(', 'static int ios_fex_fixed_window_abi(')))
        subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                        '-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-I', str(folder),
                        str(ROOT / 'tests/host/fixed_abi.c'), '-o', str(abi)], check=True)
        subprocess.run([str(abi)], check=True)


if __name__ == '__main__':
    main()
