/* iDeck, 2026-10-22. Translate opt-in fixed-image buffers at POSIX boundaries.
 * Copyright (C) 2026 iDeck contributors. LGPL-2.1-or-later. */
#ifndef IOS_FIXED_IMAGE_IO_H
#define IOS_FIXED_IMAGE_IO_H

#include <unistd.h>
#include <sys/socket.h>
#include <sys/uio.h>

ssize_t ios_fixed_read(int, void *, size_t);
ssize_t ios_fixed_write(int, const void *, size_t);
ssize_t ios_fixed_pread(int, void *, size_t, off_t);
ssize_t ios_fixed_pwrite(int, const void *, size_t, off_t);
ssize_t ios_fixed_readv(int, const struct iovec *, int);
ssize_t ios_fixed_writev(int, const struct iovec *, int);
ssize_t ios_fixed_sendmsg(int, const struct msghdr *, int);
ssize_t ios_fixed_recvmsg(int, struct msghdr *, int);
ssize_t ios_fixed_send(int, const void *, size_t, int);
ssize_t ios_fixed_recv(int, void *, size_t, int);
ssize_t ios_fixed_sendto(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
ssize_t ios_fixed_recvfrom(int, void *, size_t, int, struct sockaddr *, socklen_t *);
int ios_fixed_getsockopt(int, int, int, void *, socklen_t *);
int ios_fixed_setsockopt(int, int, int, const void *, socklen_t);

#ifndef IOS_FIXED_IMAGE_IO_IMPL
#define read(fd, buf, size) ios_fixed_read(fd, buf, size)
#define write(fd, buf, size) ios_fixed_write(fd, buf, size)
#define pread(fd, buf, size, off) ios_fixed_pread(fd, buf, size, off)
#define pwrite(fd, buf, size, off) ios_fixed_pwrite(fd, buf, size, off)
#define readv(fd, iov, count) ios_fixed_readv(fd, iov, count)
#define writev(fd, iov, count) ios_fixed_writev(fd, iov, count)
#define sendmsg(fd, msg, flags) ios_fixed_sendmsg(fd, msg, flags)
#define recvmsg(fd, msg, flags) ios_fixed_recvmsg(fd, msg, flags)
#define send(fd, buf, size, flags) ios_fixed_send(fd, buf, size, flags)
#define recv(fd, buf, size, flags) ios_fixed_recv(fd, buf, size, flags)
#define sendto(fd, buf, size, flags, addr, len) ios_fixed_sendto(fd, buf, size, flags, addr, len)
#define recvfrom(fd, buf, size, flags, addr, len) ios_fixed_recvfrom(fd, buf, size, flags, addr, len)
#define getsockopt(fd, level, opt, buf, len) ios_fixed_getsockopt(fd, level, opt, buf, len)
#define setsockopt(fd, level, opt, buf, len) ios_fixed_setsockopt(fd, level, opt, buf, len)
#endif
#endif
