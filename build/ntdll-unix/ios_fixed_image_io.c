/* iDeck, 2026-10-22. POSIX copyin/copyout cannot trigger the userspace image
 * fault handler. Resolve exact-owner image buffers before entering the kernel.
 * Copyright (C) 2026 iDeck contributors. LGPL-2.1-or-later. */
#ifndef IOS_FIXED_IMAGE_IO_IMPL
#define IOS_FIXED_IMAGE_IO_IMPL
#endif
#include "shims/ios_fixed_image_io.h"
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>

#ifndef IOV_MAX
#define IOV_MAX 1024
#endif

extern int ios_fixed_image_io_active(void);
extern void *ios_jit_current_peb(void);
extern int ios_fixed_image_translate(unsigned long long, unsigned long long, void *, unsigned long long *);

static void *image_buffer(const void *ptr, size_t size, void *owner)
{
    unsigned long long real;
    if (ptr && size && ios_fixed_image_translate((uintptr_t)ptr, size, owner, &real))
        return (void *)(uintptr_t)real;
    return (void *)ptr;
}

ssize_t ios_fixed_read(int fd, void *buf, size_t size)
{
    int saved = errno;
    if (ios_fixed_image_io_active()) buf = image_buffer(buf, size, ios_jit_current_peb());
    errno = saved;
    return read(fd, buf, size);
}

ssize_t ios_fixed_write(int fd, const void *buf, size_t size)
{
    int saved = errno;
    if (ios_fixed_image_io_active()) buf = image_buffer(buf, size, ios_jit_current_peb());
    errno = saved;
    return write(fd, buf, size);
}

ssize_t ios_fixed_pread(int fd, void *buf, size_t size, off_t offset)
{
    int saved = errno;
    if (ios_fixed_image_io_active()) buf = image_buffer(buf, size, ios_jit_current_peb());
    errno = saved;
    return pread(fd, buf, size, offset);
}

ssize_t ios_fixed_pwrite(int fd, const void *buf, size_t size, off_t offset)
{
    int saved = errno;
    if (ios_fixed_image_io_active()) buf = image_buffer(buf, size, ios_jit_current_peb());
    errno = saved;
    return pwrite(fd, buf, size, offset);
}

/* Never rewrite a caller's vector: an asynchronous caller may still own it. */
static struct iovec *image_iov(const struct iovec *input, size_t count, void *owner)
{
    struct iovec *copy;
    size_t i;
    if (!input) { errno = EFAULT; return NULL; }
    if (count > IOV_MAX) { errno = EINVAL; return NULL; }
    input = image_buffer(input, count * sizeof(*input), owner);
    if (!(copy = malloc(count * sizeof(*copy)))) { errno = ENOMEM; return NULL; }
    for (i = 0; i < count; i++)
    {
        copy[i] = input[i];
        copy[i].iov_base = image_buffer(copy[i].iov_base, copy[i].iov_len, owner);
    }
    return copy;
}

static ssize_t image_vector_io(int fd, const struct iovec *iov, int count, int writing)
{
    struct iovec *copy;
    ssize_t ret;
    int saved = errno;
    if (!ios_fixed_image_io_active() || count <= 0)
        return writing ? writev(fd, iov, count) : readv(fd, iov, count);
    if (!(copy = image_iov(iov, (size_t)count, ios_jit_current_peb()))) return -1;
    errno = saved;
    ret = writing ? writev(fd, copy, count) : readv(fd, copy, count);
    saved = errno;
    free(copy);
    errno = saved;
    return ret;
}

ssize_t ios_fixed_readv(int fd, const struct iovec *iov, int count)
{
    return image_vector_io(fd, iov, count, 0);
}

ssize_t ios_fixed_writev(int fd, const struct iovec *iov, int count)
{
    return image_vector_io(fd, iov, count, 1);
}

static ssize_t image_message_io(int fd, const struct msghdr *msg, int flags, int receiving)
{
    struct msghdr copy, *backing;
    struct iovec *iov = NULL;
    void *owner;
    ssize_t ret;
    int saved = errno;
    if (!ios_fixed_image_io_active())
        return receiving ? recvmsg(fd, (struct msghdr *)msg, flags) : sendmsg(fd, msg, flags);
    if (!msg) { errno = EFAULT; return -1; }
    owner = ios_jit_current_peb();
    backing = image_buffer(msg, sizeof(*msg), owner);
    copy = *backing;
    if ((uint64_t)copy.msg_iovlen > IOV_MAX) { errno = EINVAL; return -1; }
    if (copy.msg_iovlen)
    {
        if (!(iov = image_iov(copy.msg_iov, (size_t)copy.msg_iovlen, owner))) return -1;
        copy.msg_iov = iov;
    }
    copy.msg_name = image_buffer(copy.msg_name, copy.msg_namelen, owner);
    copy.msg_control = image_buffer(copy.msg_control, copy.msg_controllen, owner);
    errno = saved;
    ret = receiving ? recvmsg(fd, &copy, flags) : sendmsg(fd, &copy, flags);
    saved = errno;
    if (receiving && ret >= 0)
    {
        backing->msg_namelen = copy.msg_namelen;
        backing->msg_controllen = copy.msg_controllen;
        backing->msg_flags = copy.msg_flags;
    }
    free(iov);
    errno = saved;
    return ret;
}

ssize_t ios_fixed_sendmsg(int fd, const struct msghdr *msg, int flags)
{
    return image_message_io(fd, msg, flags, 0);
}

ssize_t ios_fixed_recvmsg(int fd, struct msghdr *msg, int flags)
{
    return image_message_io(fd, msg, flags, 1);
}

ssize_t ios_fixed_send(int fd, const void *buf, size_t size, int flags)
{
    int saved = errno;
    if (ios_fixed_image_io_active()) buf = image_buffer(buf, size, ios_jit_current_peb());
    errno = saved;
    return send(fd, buf, size, flags);
}

ssize_t ios_fixed_recv(int fd, void *buf, size_t size, int flags)
{
    int saved = errno;
    if (ios_fixed_image_io_active()) buf = image_buffer(buf, size, ios_jit_current_peb());
    errno = saved;
    return recv(fd, buf, size, flags);
}

ssize_t ios_fixed_sendto(int fd, const void *buf, size_t size, int flags,
                        const struct sockaddr *addr, socklen_t len)
{
    int saved = errno;
    if (ios_fixed_image_io_active())
    {
        void *owner = ios_jit_current_peb();
        buf = image_buffer(buf, size, owner);
        addr = image_buffer(addr, len, owner);
    }
    errno = saved;
    return sendto(fd, buf, size, flags, addr, len);
}

ssize_t ios_fixed_recvfrom(int fd, void *buf, size_t size, int flags,
                          struct sockaddr *addr, socklen_t *len)
{
    int saved = errno;
    if (ios_fixed_image_io_active())
    {
        void *owner = ios_jit_current_peb();
        buf = image_buffer(buf, size, owner);
        if (addr && len)
        {
            len = image_buffer(len, sizeof(*len), owner);
            addr = image_buffer(addr, *len, owner);
        }
    }
    errno = saved;
    return recvfrom(fd, buf, size, flags, addr, len);
}

int ios_fixed_getsockopt(int fd, int level, int option, void *buf, socklen_t *len)
{
    int saved = errno;
    if (ios_fixed_image_io_active() && len)
    {
        void *owner = ios_jit_current_peb();
        len = image_buffer(len, sizeof(*len), owner);
        buf = image_buffer(buf, *len, owner);
    }
    errno = saved;
    return getsockopt(fd, level, option, buf, len);
}

int ios_fixed_setsockopt(int fd, int level, int option, const void *buf, socklen_t len)
{
    int saved = errno;
    if (ios_fixed_image_io_active()) buf = image_buffer(buf, len, ios_jit_current_peb());
    errno = saved;
    return setsockopt(fd, level, option, buf, len);
}
