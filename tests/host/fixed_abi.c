/* iDeck-BCD, 2026-10-23: stale PE metadata must not fault while unmapping. */
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

typedef uint32_t DWORD;
typedef uint16_t WORD;
typedef struct { WORD e_magic; char rest[58]; int32_t e_lfanew; } IMAGE_DOS_HEADER;
typedef struct { DWORD VirtualAddress, Size; } IMAGE_DATA_DIRECTORY;
typedef struct {
    DWORD Signature;
    char file_header[20];
    struct { WORD Magic; char rest[106]; DWORD NumberOfRvaAndSizes;
             IMAGE_DATA_DIRECTORY DataDirectory[16]; } OptionalHeader;
} IMAGE_NT_HEADERS64;
typedef struct {
    DWORD Characteristics, TimeDateStamp;
    WORD MajorVersion, MinorVersion;
    DWORD Name, Base, NumberOfFunctions, NumberOfNames;
    DWORD AddressOfFunctions, AddressOfNames, AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY;
#define IMAGE_DOS_SIGNATURE 0x5a4d
#define IMAGE_NT_SIGNATURE 0x4550
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC 0x20b
#define IMAGE_DIRECTORY_ENTRY_EXPORT 0
_Static_assert(sizeof(IMAGE_DOS_HEADER) == 64, "DOS layout");
_Static_assert(sizeof(IMAGE_NT_HEADERS64) == 264, "NT layout");
_Static_assert(offsetof(IMAGE_NT_HEADERS64, OptionalHeader.DataDirectory) == 136, "directory layout");
_Static_assert(sizeof(IMAGE_EXPORT_DIRECTORY) == 40, "export layout");

static unsigned char *image, *inaccessible;
static size_t page_size;
static unsigned reads, fail_read;
typedef uintptr_t mach_vm_address_t;
typedef size_t mach_vm_size_t;
#define KERN_SUCCESS 0
static int mach_task_self(void) { return 1; }
static int mach_vm_read_overwrite(int task, uintptr_t addr, size_t size, uintptr_t out, size_t *got)
{
    assert(task == 1);
    ++reads;
    *got = 0;
    if (reads == fail_read || addr < (uintptr_t)image || size > page_size ||
        addr - (uintptr_t)image > page_size - size) return 1;
    memcpy((void *)out, (void *)addr, size);
    *got = size;
    return 0;
}
static struct { void *pe_base; size_t size; void *map_peb, *owner_peb; int unmapped; } ios_jit_mappings[3];
static int ios_jit_mapping_count = 3;
#include "fixed-abi.inc"

static void make_image(void)
{
    IMAGE_DOS_HEADER dos = { .e_magic = IMAGE_DOS_SIGNATURE, .e_lfanew = 0x80 };
    IMAGE_NT_HEADERS64 nt = { .Signature = IMAGE_NT_SIGNATURE };
    IMAGE_EXPORT_DIRECTORY exp = { .Name = 0x300, .NumberOfFunctions = 1, .NumberOfNames = 1,
        .AddressOfFunctions = 0x350, .AddressOfNames = 0x354, .AddressOfNameOrdinals = 0x358 };
    DWORD rva = 0x380, name = 0x320;
    uint64_t abi[] = {0x314e49574744494dull, 0x8000000000000000ull, 128};
    nt.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    nt.OptionalHeader.NumberOfRvaAndSizes = 16;
    nt.OptionalHeader.DataDirectory[0] = (IMAGE_DATA_DIRECTORY){0x200, 0x100};
    memset(image, 0, page_size);
    memcpy(image, &dos, sizeof(dos)); memcpy(image + 0x80, &nt, sizeof(nt));
    memcpy(image + 0x200, &exp, sizeof(exp));
    strcpy((char *)image + 0x300, "libarm64ecfex.dll");
    strcpy((char *)image + 0x320, "IosGuestWindowAbi");
    memcpy(image + 0x350, &rva, 4); memcpy(image + 0x354, &name, 4);
    memcpy(image + 0x380, abi, sizeof(abi));
    reads = fail_read = 0;
}

static void invalid32(size_t at, DWORD value)
{
    make_image(); memcpy(image + at, &value, 4);
    assert(!ios_fixed_pe_abi((uintptr_t)image, page_size));
}

int main(void)
{
    int owner, other;
    page_size = (size_t)sysconf(_SC_PAGESIZE);
    image = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    inaccessible = mmap(NULL, page_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(image != MAP_FAILED && inaccessible != MAP_FAILED);
    make_image();
    assert(ios_fixed_pe_abi((uintptr_t)image, page_size));
    unsigned total_reads = reads;
    for (unsigned i = 1; i <= total_reads; ++i)
    {
        reads = 0; fail_read = i;
        assert(!ios_fixed_pe_abi((uintptr_t)image, page_size));
    }
    fail_read = 0;
    assert(!ios_fixed_pe_abi((uintptr_t)inaccessible, page_size));
    assert(!ios_fixed_pe_abi(UINTPTR_MAX - 8, page_size));
    invalid32(0x3c, UINT32_MAX); /* negative lfanew */
    invalid32(0x80, 0); /* PE signature */
    invalid32(0x98, 0x10b); /* wrong optional header */
    invalid32(0x104, 0); /* missing directories */
    invalid32(0x108, UINT32_MAX); /* export RVA */
    invalid32(0x10c, UINT32_MAX); /* export size */
    invalid32(0x20c, UINT32_MAX); /* module name */
    invalid32(0x214, 65537); /* function count */
    invalid32(0x218, 2); /* name count > function count */
    invalid32(0x21c, UINT32_MAX); /* address table */
    invalid32(0x220, UINT32_MAX); /* name table */
    invalid32(0x224, UINT32_MAX); /* ordinal table */
    invalid32(0x354, UINT32_MAX); /* export name */
    invalid32(0x358, 1); /* ordinal >= function count */
    invalid32(0x350, 0x200); /* forwarder */
    invalid32(0x350, (DWORD)page_size - 8); /* truncated ABI */
    invalid32(0x380, 0); /* wrong magic */
    invalid32(0x388, 1); /* wrong tag */
    invalid32(0x390, 127); /* incompatible window capacity */
    make_image(); memset(image + 0x300, 'x', 64);
    assert(!ios_fixed_pe_abi((uintptr_t)image, page_size));
    make_image();
    ios_jit_mappings[0].pe_base = inaccessible;
    ios_jit_mappings[0].size = page_size;
    ios_jit_mappings[0].map_peb = &owner;
    ios_jit_mappings[1] = ios_jit_mappings[0];
    ios_jit_mappings[1].unmapped = 1;
    ios_jit_mappings[2] = ios_jit_mappings[0];
    ios_jit_mappings[2].pe_base = image;
    assert(ios_fex_fixed_window_abi(&owner)); /* unreadable/stale entries before live FEX */
    assert(!ios_fex_fixed_window_abi(&other));
    ios_jit_mappings[2].unmapped = 1;
    assert(!ios_fex_fixed_window_abi(&owner));
    munmap(image, page_size); munmap(inaccessible, page_size);
    puts("PASS: production fixed-image ABI probe rejects stale/unreadable PEs and malformed export bounds");
}
