/* iDeck-BCD, 2026-10-22: same-address x64 process isolation regression.
 * Build twice with FIXED_TEST_ROLE 1/2; both images have stripped relocations.
 * The parent stays alive while the child changes its private image data and
 * executes a different instruction at the same guest RIP.
 */
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef FIXED_TEST_ROLE
#error FIXED_TEST_ROLE must be 1 (parent) or 2 (child)
#endif

#define IMAGE_BASE ((uintptr_t)0x140000000ULL)
#define ROUNDS 32
#define TIMEOUT_MS 15000
#define INITIAL_COOKIE 0x13579bdfUL

static volatile unsigned long cookie = INITIAL_COOKIE;
static volatile unsigned long *volatile cookie_pointer = &cookie;
static volatile unsigned role = FIXED_TEST_ROLE;

/* A native Wine critical section in fixed image data reproduces the 1C fault. */
static CRITICAL_SECTION image_lock;
static unsigned locked_count;

static DWORD WINAPI lock_worker(void *unused)
{
    unsigned i;
    (void)unused;
    for (i = 0; i < 128; ++i)
    {
        EnterCriticalSection(&image_lock);
        ++locked_count;
        LeaveCriticalSection(&image_lock);
    }
    return 0;
}

static int check_image_lock(void)
{
    HANDLE worker;
    DWORD status;
    if (!InitializeCriticalSectionAndSpinCount(&image_lock, 4000)) return 0;
    EnterCriticalSection(&image_lock);
    if (!TryEnterCriticalSection(&image_lock)) return 0;
    LeaveCriticalSection(&image_lock);
    worker = CreateThread(NULL, 0, lock_worker, NULL, 0, NULL);
    LeaveCriticalSection(&image_lock);
    if (!worker) return 0;
    lock_worker(NULL);
    if (WaitForSingleObject(worker, TIMEOUT_MS) != WAIT_OBJECT_0 ||
        !GetExitCodeThread(worker, &status) || status || locked_count != 256) return 0;
    CloseHandle(worker);
    DeleteCriticalSection(&image_lock);
    printf("[fixed-image-test] PASS: image critical section, recursive entry and 256 threaded updates\n");
    return 1;
}

__declspec(noinline) unsigned fixed_code_identity(void)
{
    return FIXED_TEST_ROLE;
}

static unsigned (*volatile code_pointer)(void) = fixed_code_identity;

static int check_private_image(unsigned expected_role, unsigned long expected_cookie)
{
    if ((uintptr_t)GetModuleHandleA(NULL) != IMAGE_BASE || role != expected_role ||
        cookie_pointer != &cookie || *cookie_pointer != expected_cookie ||
        code_pointer != fixed_code_identity || code_pointer() != expected_role)
    {
        printf("[fixed-image-test] FAIL role=%u code=%u cookie=%08lx image=%p\n",
               role, code_pointer(), cookie, (void *)GetModuleHandleA(NULL));
        return 0;
    }
    return 1;
}

static void event_name(char *buffer, size_t size, DWORD parent, const char *kind)
{
    snprintf(buffer, size, "Local\\iDeckFixedImage-%lu-%s", (unsigned long)parent, kind);
}

static int child(DWORD parent)
{
    char name[96];
    HANDLE go, done;
    unsigned i;
    event_name(name, sizeof(name), parent, "go");
    go = OpenEventA(SYNCHRONIZE, FALSE, name);
    event_name(name, sizeof(name), parent, "done");
    done = OpenEventA(EVENT_MODIFY_STATE, FALSE, name);
    if (!go || !done || !check_private_image(2, INITIAL_COOKIE)) return 51;
    for (i = 0; i < ROUNDS; ++i)
    {
        if (WaitForSingleObject(go, TIMEOUT_MS) != WAIT_OBJECT_0) return 52;
        cookie = 0xc2000000UL + i;
        if (!check_private_image(2, 0xc2000000UL + i)) return 53;
        if (!SetEvent(done)) return 54;
    }
    CloseHandle(go);
    CloseHandle(done);
    return 42;
}

static int parent(void)
{
    char path[MAX_PATH], command[MAX_PATH + 64], name[96];
    char *slash;
    STARTUPINFOA startup = {0};
    PROCESS_INFORMATION process = {0};
    HANDLE go = NULL, done = NULL;
    DWORD length, status = 0;
    unsigned i;
    int pass = 0;

    if (!check_private_image(1, INITIAL_COOKIE)) return 1;
    length = GetModuleFileNameA(NULL, path, sizeof(path));
    if (!length || length >= sizeof(path)) return 2;
    slash = strrchr(path, '\\');
    if (!slash || (size_t)(slash - path) + sizeof("\\fixed-child.exe") > sizeof(path)) return 3;
    strcpy(slash + 1, "fixed-child.exe");
    snprintf(command, sizeof(command), "\"%s\" %lu", path, (unsigned long)GetCurrentProcessId());
    event_name(name, sizeof(name), GetCurrentProcessId(), "go");
    go = CreateEventA(NULL, FALSE, FALSE, name);
    event_name(name, sizeof(name), GetCurrentProcessId(), "done");
    done = CreateEventA(NULL, FALSE, FALSE, name);
    if (!go || !done) goto cleanup;

    cookie = 0xa1000000UL;
    startup.cb = sizeof(startup);
    if (!CreateProcessA(path, command, NULL, NULL, FALSE, 0, NULL, NULL, &startup, &process))
    {
        printf("[fixed-image-test] CreateProcess failed err=%lu\n", (unsigned long)GetLastError());
        goto cleanup;
    }
    for (i = 0; i < ROUNDS; ++i)
    {
        if (!check_private_image(1, 0xa1000000UL + i) || !SetEvent(go)) goto cleanup;
        if (WaitForSingleObject(done, TIMEOUT_MS) != WAIT_OBJECT_0) goto cleanup;
        if (!check_private_image(1, 0xa1000000UL + i)) goto cleanup;
        cookie = 0xa1000000UL + i + 1;
    }
    if (WaitForSingleObject(process.hProcess, TIMEOUT_MS) != WAIT_OBJECT_0 ||
        !GetExitCodeProcess(process.hProcess, &status) || status != 42 ||
        !check_private_image(1, 0xa1000000UL + ROUNDS)) goto cleanup;
    pass = 1;

cleanup:
    if (process.hProcess)
    {
        if (!pass) TerminateProcess(process.hProcess, 90);
        CloseHandle(process.hProcess);
        CloseHandle(process.hThread);
    }
    if (go) CloseHandle(go);
    if (done) CloseHandle(done);
    printf("[fixed-image-test] %s: %u simultaneous same-base rounds, child exit=%lu\n",
           pass ? "PASS" : "FAIL", pass ? ROUNDS : 0, (unsigned long)status);
    return pass ? 0 : 1;
}

int main(int argc, char **argv)
{
    if (!check_image_lock())
    {
        printf("[fixed-image-test] FAIL: native critical section in fixed image\n");
        return 55;
    }
    if (argc == 2)
    {
        char *end;
        unsigned long parent_id;
        parent_id = strtoul(argv[1], &end, 10);
        if (!parent_id || *end) return 50;
        return child((DWORD)parent_id);
    }
    if (argc != 1) return 50;
    return parent();
}
