/*
 * linux_preload.c — LD_PRELOAD loader for the KLINIKAL Linux socket stack.
 *
 * This is NOT a translation shim: the Go module (linuxsock/) implements the
 * POSIX socket API natively — fd-numbered operations, Linux errno errors,
 * glibc fd_set/pollfd/addrinfo layouts, Linux option/ioctl numbers. The
 * loader's only jobs are:
 *   1. interpose the libc socket entry points and route AF_INET/AF_INET6
 *      socket fds into the embedded WireGuard userspace stack (go_*
 *      exports); everything else (AF_UNIX, pipes, files) passes through
 *      to the real libc via RTLD_NEXT;
 *   2. own the fd namespace: fake fds are allocated below FD_SETSIZE
 *      from reserved slots (kl_alloc_fd) so CPython's fd_set bitmaps
 *      stay valid, and the same fd number is what the Go side keys on;
 *   3. emulate epoll for tunnel fds via the eventfd bridge, and split
 *      mixed real+tunnel select/poll across the two backends.
 *
 * Fake-ness of an fd is a table lookup (kl_fake), not a range test.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/sysmacros.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

/* ---- Go-exported functions (from exports.go / init_linux.go) ----
 * The surface is the POSIX socket API itself; fd numbers and struct
 * layouts are passed through unchanged. */
extern int go_socket(int fd, int domain, int type, int protocol);
extern int go_dup(int oldfd, int newfd);
extern int go_close(int fd);
extern int go_connect(int fd, void *name, int namelen);
extern int go_bind(int fd, void *name, int namelen);
extern int go_listen(int fd, int backlog);
extern int go_accept(int listenfd, int newfd, void *addr, int *addrlen);
extern int go_send(int fd, void *buf, int len, int flags);
extern int go_recv(int fd, void *buf, int len, int flags);
extern int go_sendto(int fd, void *buf, int len, int flags,
                     void *to, int tolen);
extern int go_recvfrom(int fd, void *buf, int len, int flags,
                       void *from, int *fromlen);
extern int go_setsockopt(int fd, int level, int optname,
                         void *optval, int optlen);
extern int go_getsockopt(int fd, int level, int optname,
                         void *optval, int *optlen);
extern int go_getsockname(int fd, void *name, int *namelen);
extern int go_getpeername(int fd, void *name, int *namelen);
extern int go_shutdown(int fd, int how);
extern int go_getaddrinfo(char *node, char *service, void *hints,
                          void **res);
extern void go_freeaddrinfo(void *ai);
extern int go_addrinfo_owned(void *ai);
extern int go_ioctl(int fd, unsigned long request, unsigned int *argp);
extern int go_select(int nfds, void *readfds, void *writefds,
                     void *exceptfds, void *timeout);
extern int go_poll(void *fds, int nfds, int timeout);
extern int go_start_notify(int fd);
void kl_ep_purge_fd_fwd(int fd);
static void kl_ep_purge_locked(int fd);
extern int klinikal_init(char *path);
extern int klinikal_last_error(void);

/* the Go side reports Linux errno values directly */
#define KL_FAIL() (errno = klinikal_last_error(), -1)

/* ---- fd space: fake fds allocated below FD_SETSIZE ----
 * CPython's internal connect-wait and its select module use fd_set
 * bitmaps (FD_SETSIZE=1024), so fake fds must stay below 1024. Each
 * fake fd number is reserved with a hidden /dev/null fd so the kernel
 * never hands that number to the app; fake-ness is a table lookup.
 * The fd number IS the identity used by the Go stack — there is no
 * separate handle space. */
#define KL_FD_MAX 1024
static uint8_t kl_fake[KL_FD_MAX];

#define KL_IS_FAKE(fd) ((fd) >= 0 && (fd) < KL_FD_MAX && kl_fake[fd])

static int kl_alloc_fd(void);
static void kl_release(int fd);

/* ---- libc passthrough handles ---- */
static int (*real_socket)(int, int, int);
static int (*real_close)(int);
typedef int (*close_range_t)(unsigned int, unsigned int, int);
static close_range_t real_close_range = NULL;
static int (*real_fcntl)(int, int, ...);
static int (*real_dup)(int);
static int (*real_dup2)(int, int);
static ssize_t (*real_sendmsg)(int, const struct msghdr *, int);
static ssize_t (*real_recvmsg)(int, struct msghdr *, int);
static int (*real_ioctl)(int, unsigned long, void *);
static int (*real_getaddrinfo)(const char *, const char *,
                               const struct addrinfo *, struct addrinfo **);
static void (*real_freeaddrinfo)(struct addrinfo *);
static int (*real_select)(int, fd_set *, fd_set *, fd_set *, struct timeval *);
static int (*real_poll)(struct pollfd *, nfds_t, int);
static int (*real_epoll_create1)(int);
static int (*real_epoll_ctl)(int, int, int, struct epoll_event *);
static int (*real_epoll_wait)(int, struct epoll_event *, int, int);
static int (*real_connect)(int, const struct sockaddr *, socklen_t);
static int (*real_bind)(int, const struct sockaddr *, socklen_t);
static int (*real_listen)(int, int);
static int (*real_accept)(int, struct sockaddr *, socklen_t *);
static ssize_t (*real_send)(int, const void *, size_t, int);
static ssize_t (*real_recv)(int, void *, size_t, int);
static ssize_t (*real_sendto)(int, const void *, size_t, int,
                              const struct sockaddr *, socklen_t);
static ssize_t (*real_recvfrom)(int, void *, size_t, int,
                                struct sockaddr *, socklen_t *);
static int (*real_setsockopt)(int, int, int, const void *, socklen_t);
static int (*real_getsockopt)(int, int, int, void *, socklen_t *);
static int (*real_getsockname)(int, struct sockaddr *, socklen_t *);
static int (*real_getpeername)(int, struct sockaddr *, socklen_t *);
static int (*real_shutdown)(int, int);

/* table mutation lock: allocation, release, dup, epoll registrations.
 * Lock-free reads of kl_fake are benign races (byte-sized; a stale read
 * right after close only delays the EBADF by one call). */
static pthread_mutex_t kl_tbl_mu = PTHREAD_MUTEX_INITIALIZER;

/* ---- non-blocking mode tracking (mirrored for F_GETFL honesty) ---- */
static uint8_t kl_nb[KL_FD_MAX];

static int kl_dom[KL_FD_MAX], kl_typ[KL_FD_MAX];
static void kl_set_nb(int fd, int on) {
    unsigned int v = (unsigned int)on;
    go_ioctl(fd, FIONBIO, &v);
    if (fd >= 0 && fd < KL_FD_MAX)
        kl_nb[fd] = (uint8_t)on;
}

/* allocate a fake fd below FD_SETSIZE, reserving the number with a
 * hidden /dev/null fd so the kernel never gives it to the app */
static int kl_alloc_fd_at(int want);
static int kl_alloc_fd_from(int start);
/* The kernel's own allocation IS the reservation: open() returns the
 * lowest free fd atomically, so no concurrent get_unused/fd_install
 * can clobber it (that window only fools table-inspecting syscalls
 * like dup3). The only constraint is staying below FD_SETSIZE. */
static int kl_alloc_fd(void) {
    int r = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (r < 0) return -1;
    if (r >= KL_FD_MAX) { close(r); errno = EMFILE; return -1; }
    kl_fake[r] = 1;
    return r;
}
static int kl_alloc_fd_from(int start) {
    if (start < 3) start = 3;
    pthread_mutex_lock(&kl_tbl_mu);
    for (int fd = start; fd < KL_FD_MAX; fd++) {
        int r = kl_alloc_fd_at(fd);
        if (r == fd) { pthread_mutex_unlock(&kl_tbl_mu); return fd; }
    }
    pthread_mutex_unlock(&kl_tbl_mu);
    errno = EMFILE;
    return -1;
}
/* reserve exactly slot `want` (caller holds kl_tbl_mu for the scan path).
 * The reservation must be atomic: a bare F_GETFD check followed by dup2
 * can silently clobber an fd the kernel just handed to another thread
 * (e.g. its epoll fd -> epoll_wait then fails with EINVAL on the
 * /dev/null stand-in). dup3 fails with EBUSY if the slot got taken. */
/* true iff fd currently holds OUR /dev/null placeholder. The kernel
 * can clobber a slot we just dup3-ed: another thread's fd allocation
 * reserves the number (get_unused_fd) before installing the file
 * (fd_install), and in that window the slot reads as free to both
 * F_GETFD and dup3, and fd_install then overwrites unconditionally.
 * No user-side check-then-install closes that window, so we detect
 * the takeover instead: our placeholder is always /dev/null. */
static int kl_slot_ours(int fd) {
    struct stat st;
    if (fstat(fd, &st) != 0) return 0;
    return S_ISCHR(st.st_mode) && st.st_rdev == makedev(1, 3);
}

static int kl_alloc_fd_at(int want) {
    if (want < 3 || want >= KL_FD_MAX) { errno = EBADF; return -1; }
    if (real_fcntl(want, F_GETFD) != -1 || errno != EBADF) return -1; /* busy fast path */
    int r = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (r < 0) return -1;
    if (r != want) {
        if (dup3(r, want, O_CLOEXEC) != want) { close(r); return -1; } /* EBUSY: taken under us */
        close(r);
    }
    if (!kl_slot_ours(want)) {   /* kernel fd_install overwrote us: not ours anymore */
        kl_fake[want] = 0;       /* do NOT close: the slot belongs to the app now */
        return -1;
    }
    kl_fake[want] = 1;
    if (getenv("KLINIKAL_VERBOSE"))
        fprintf(stderr, "kl: reserved slot=%d\n", want);
    return want;
}
static void kl_release(int fd) {
    pthread_mutex_lock(&kl_tbl_mu);
    kl_fake[fd] = 0;
    pthread_mutex_unlock(&kl_tbl_mu);
}

static void kl_ensure(void) {
    static int inited = 0;
    if (inited) return;
    real_socket = dlsym(RTLD_NEXT, "socket");
    real_close  = dlsym(RTLD_NEXT, "close");
    real_close_range = (close_range_t)dlsym(RTLD_NEXT, "close_range");
    real_fcntl  = dlsym(RTLD_NEXT, "fcntl");
    real_dup    = dlsym(RTLD_NEXT, "dup");
    real_dup2   = dlsym(RTLD_NEXT, "dup2");
    real_sendmsg = dlsym(RTLD_NEXT, "sendmsg");
    real_recvmsg = dlsym(RTLD_NEXT, "recvmsg");
    real_ioctl  = dlsym(RTLD_NEXT, "ioctl");
    real_getaddrinfo   = dlsym(RTLD_NEXT, "getaddrinfo");
    real_freeaddrinfo  = dlsym(RTLD_NEXT, "freeaddrinfo");
    real_select = dlsym(RTLD_NEXT, "select");
    real_poll   = dlsym(RTLD_NEXT, "poll");
    real_epoll_create1 = dlsym(RTLD_NEXT, "epoll_create1");
    real_epoll_ctl = dlsym(RTLD_NEXT, "epoll_ctl");
    real_epoll_wait = dlsym(RTLD_NEXT, "epoll_wait");
    real_connect = dlsym(RTLD_NEXT, "connect");
    real_bind = dlsym(RTLD_NEXT, "bind");
    real_listen = dlsym(RTLD_NEXT, "listen");
    real_accept = dlsym(RTLD_NEXT, "accept");
    real_send = dlsym(RTLD_NEXT, "send");
    real_recv = dlsym(RTLD_NEXT, "recv");
    real_sendto = dlsym(RTLD_NEXT, "sendto");
    real_recvfrom = dlsym(RTLD_NEXT, "recvfrom");
    real_setsockopt = dlsym(RTLD_NEXT, "setsockopt");
    real_getsockopt = dlsym(RTLD_NEXT, "getsockopt");
    real_getsockname = dlsym(RTLD_NEXT, "getsockname");
    real_getpeername = dlsym(RTLD_NEXT, "getpeername");
    real_shutdown = dlsym(RTLD_NEXT, "shutdown");
    const char *cfg = getenv("KLINIKAL_WG_CONF");
    if (!cfg) cfg = "./wg.conf";
    if (klinikal_init((char *)cfg) != 0)
        fprintf(stderr, "klinikal: failed to init WireGuard stack from %s\n", cfg);
    else
        fprintf(stderr, "klinikal: WireGuard stack active from %s\n", cfg);
    inited = 1;
}

__attribute__((constructor)) static void kl_ctor(void) { kl_ensure(); }

/* ---- socket lifecycle ---- */
/* Routing rule: only AF_INET/AF_INET6 stream/dgram sockets become
 * fake fds. AF_INET6 is accepted because dual-stack clients (gRPC)
 * create v6 sockets and connect to v4-mapped ::ffff:a.b.c.d
 * addresses, which the stack maps to IPv4; true v6 targets fail
 * routing later. Every other domain (AF_UNIX, ...) is the kernel's. */
int socket(int domain, int type, int protocol) {
    if (domain != AF_INET && domain != AF_INET6)
        return real_socket(domain, type, protocol);
    int t = type & ~(SOCK_NONBLOCK | SOCK_CLOEXEC);
    if (t != SOCK_STREAM && t != SOCK_DGRAM)
        return real_socket(domain, type, protocol);
    int fd = kl_alloc_fd();
    if (fd < 0) return -1;
    if (go_socket(fd, domain, t, protocol) != 0) {
        int e = klinikal_last_error();
        kl_release(fd);
        real_close(fd);
        errno = e ? e : ENOENT;
        return -1;
    }
    kl_dom[fd] = domain; kl_typ[fd] = t; kl_nb[fd] = 0;
    if (type & SOCK_NONBLOCK) kl_set_nb(fd, 1);
    return fd;
}

/* close_range: glibc symbol path. CPython's os.close_range may call
 * this wrapper (interposable) or the raw syscall (not interposable);
 * the regression test tells us which. Fake fds must go through our
 * close() so the Go registration and kl_fake entry die with them. */
int close_range(unsigned int first, unsigned int last, int flags) {
    if (flags != 0) { errno = EINVAL; return -1; }
    int any_fake = 0;
    for (unsigned f = first; f <= last && f < KL_FD_MAX; f++)
        if (kl_fake[f]) { any_fake = 1; break; }
    if (!any_fake) {
        if (real_close_range) return real_close_range(first, last, flags);
        for (unsigned f = first; f <= last; f++)
            if (real_close((int)f) != 0 && errno != EBADF) return -1;
        return 0;
    }
    /* close_range ignores EBADF inside the range; mirror that */
    for (unsigned f = first; f <= last; f++) {
        if (close((int)f) != 0 && errno != EBADF) return -1;
    }
    return 0;
}

// close: for a fake fd, drop the epoll registrations, let the Go side
// refcount the aliases, release our /dev/null reservation, then close
// the reservation fd itself (the number returns to the kernel).
int close(int fd) {
    if (getenv("KLINIKAL_VERBOSE"))
        fprintf(stderr, "kl: close fd=%d fake=%d\n", fd,
                (fd >= 0 && fd < KL_FD_MAX) ? kl_fake[fd] : -1);
    if (KL_IS_FAKE(fd)) {
        kl_ep_purge_fd_fwd(fd);
        go_close(fd); /* Go refcounts dup aliases internally */
        kl_release(fd);
        return real_close(fd); /* release the reservation fd */
    }
    return real_close(fd);
}

/* Loopback must stay on the kernel: every injected process embeds its
 * OWN stack, so 127.0.0.1 cannot be an IPC path between two of them
 * (Ray's driver<->raylet<->GCS, multiprocessing, health checks all use
 * it). When bind/connect names a loopback address on a fake fd, convert
 * the fd in place: build a real socket, dup2 it over the placeholder
 * (raw syscall: the fd number never changes), mirror the options that
 * matter before bind, and drop the stack registration. */
static int kl_is_loopback(const struct sockaddr *a, socklen_t l) {
    if (!a) return 0;
    if (a->sa_family == AF_INET && l >= (socklen_t)sizeof(struct sockaddr_in))
        return (((const struct sockaddr_in *)a)->sin_addr.s_addr
                & htonl(0xff000000u)) == htonl(0x7f000000u);
    if (a->sa_family == AF_INET6 && l >= (socklen_t)sizeof(struct sockaddr_in6))
        return IN6_IS_ADDR_LOOPBACK(
            &((const struct sockaddr_in6 *)a)->sin6_addr);
    return 0;
}
static void kl_swap_to_real(int fd) {
    int r = real_socket(kl_dom[fd], kl_typ[fd], 0);
    if (r < 0) return;   /* keep fake; the stack path will error */
    int v = 0, vl = sizeof(v);
    if (go_getsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &v, &vl) == 0 && v) {
        int one = 1;
        real_setsockopt(r, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    }
    if (kl_nb[fd]) real_fcntl(r, F_SETFL, O_NONBLOCK);
    if (syscall(SYS_dup2, r, fd) < 0) { real_close(r); return; }
    real_close(r);
    go_close(fd);
    kl_fake[fd] = 0; kl_nb[fd] = 0;
    kl_ep_purge_fd_fwd(fd);
}

int connect(int fd, const struct sockaddr *addr, socklen_t len) {
    if (KL_IS_FAKE(fd)) {
        if (kl_is_loopback(addr, len)) kl_swap_to_real(fd);
        else { if (go_connect(fd, (void *)addr, (int)len) != 0) return KL_FAIL();
               return 0; }
    }
    return real_connect(fd, addr, len);
}

int bind(int fd, const struct sockaddr *addr, socklen_t len) {
    if (KL_IS_FAKE(fd)) {
        if (kl_is_loopback(addr, len)) kl_swap_to_real(fd);
        else { if (go_bind(fd, (void *)addr, (int)len) != 0) return KL_FAIL();
               return 0; }
    }
    return real_bind(fd, addr, len);
}

int listen(int fd, int backlog) {
    if (!KL_IS_FAKE(fd)) return real_listen(fd, backlog);
    if (go_listen(fd, backlog) != 0) return KL_FAIL();
    return 0;
}

int accept(int fd, struct sockaddr *addr, socklen_t *len) {
    if (!KL_IS_FAKE(fd)) return real_accept(fd, addr, len);
    int cfd = kl_alloc_fd();
    if (cfd < 0) return -1;
    kl_dom[cfd] = kl_dom[fd]; kl_typ[cfd] = kl_typ[fd];
    if (go_accept(fd, cfd, addr, (int *)len) != 0) {
        int e = klinikal_last_error();
        kl_release(cfd);
        real_close(cfd);
        errno = e ? e : ENOTCONN;
        return -1;
    }
    return cfd;
}

/* ---- data transfer ---- */
ssize_t send(int fd, const void *buf, size_t len, int flags) {
    if (!KL_IS_FAKE(fd)) return real_send(fd, buf, len, flags);
    int r = go_send(fd, (void *)buf, (int)len, flags);
    return r < 0 ? KL_FAIL() : r;
}

ssize_t recv(int fd, void *buf, size_t len, int flags) {
    if (!KL_IS_FAKE(fd)) return real_recv(fd, buf, len, flags);
    int r = go_recv(fd, buf, (int)len, flags);
    return r < 0 ? KL_FAIL() : r;
}

ssize_t sendto(int fd, const void *buf, size_t len, int flags,
               const struct sockaddr *to, socklen_t tolen) {
    if (!KL_IS_FAKE(fd)) return real_sendto(fd, buf, len, flags, to, tolen);
    int r = go_sendto(fd, (void *)buf, (int)len, flags,
                      (void *)to, (int)tolen);
    return r < 0 ? KL_FAIL() : r;
}

ssize_t recvfrom(int fd, void *buf, size_t len, int flags,
                 struct sockaddr *from, socklen_t *fromlen) {
    if (!KL_IS_FAKE(fd)) return real_recvfrom(fd, buf, len, flags, from, fromlen);
    int r = go_recvfrom(fd, buf, (int)len, flags,
                        from, (int *)fromlen);
    if (r < 0 && from && klinikal_last_error() == EINVAL /* stream socket,
        no per-datagram address: fall back to recv + getpeername */) {
        r = go_recv(fd, buf, (int)len, flags);
        if (r >= 0) {
            int al = (int)*fromlen;
            if (go_getpeername(fd, from, &al) == 0) *fromlen = al;
        }
    }
    return r < 0 ? KL_FAIL() : r;
}

// accept4: accept, then apply SOCK_NONBLOCK/SOCK_CLOEXEC on the new fd.
int accept4(int fd, struct sockaddr *addr, socklen_t *len, int flags) {
    int cfd = accept(fd, addr, len);
    if (cfd < 0) return cfd;
    if (flags & SOCK_NONBLOCK) kl_set_nb(cfd, 1);
    if (flags & SOCK_CLOEXEC) real_fcntl(cfd, F_SETFD, FD_CLOEXEC);
    return cfd;
}

/* dup/dup2 on tunnel fds alias the same socket; the Go side refcounts,
 * so the underlying socket closes only with the last alias. */
int dup(int oldfd) {
    if (!KL_IS_FAKE(oldfd)) return real_dup(oldfd);
    int n = kl_alloc_fd();
    if (n < 0) return -1;
    if (go_dup(oldfd, n) != 0) {
        int e = klinikal_last_error();
        kl_release(n);
        real_close(n);
        errno = e ? e : EBADF;
        return -1;
    }
    kl_nb[n] = kl_nb[oldfd];
    return n;
}
int dup2(int oldfd, int newfd) {
    if (newfd < 0 || newfd >= KL_FD_MAX + 4096) { errno = EBADF; return -1; }
    if (!KL_IS_FAKE(oldfd)) {
        /* real -> new: free a fake target first, then kernel dup2 */
        if (KL_IS_FAKE(newfd)) {
            go_close(newfd);
            kl_release(newfd);
            real_close(newfd);
        }
        return real_dup2(oldfd, newfd);
    }
    if (oldfd == newfd) return newfd;
    pthread_mutex_lock(&kl_tbl_mu);
    if (KL_IS_FAKE(newfd)) {
        kl_ep_purge_locked(newfd);
        go_close(newfd);
        kl_release(newfd);
        real_close(newfd);
    } else if (real_fcntl(newfd, F_GETFD) != -1) {
        real_close(newfd);
    }
    int r = kl_alloc_fd_at(newfd);
    if (r == newfd) {
        if (go_dup(oldfd, newfd) != 0) {
            kl_release(newfd);
            real_close(newfd);
            r = -1;
        } else {
            kl_nb[newfd] = kl_nb[oldfd];
        }
    }
    pthread_mutex_unlock(&kl_tbl_mu);
    return r == newfd ? newfd : -1;
}

int dup3(int oldfd, int newfd, int flags) {
    if (oldfd == newfd) { errno = EINVAL; return -1; }
    if (flags & ~O_CLOEXEC) { errno = EINVAL; return -1; }
    int r = dup2(oldfd, newfd);
    if (r >= 0 && KL_IS_FAKE(r)) {
        int fl = real_fcntl(r, F_GETFD);
        if (fl >= 0) real_fcntl(r, F_SETFD, fl | (flags & O_CLOEXEC ? FD_CLOEXEC : 0));
    }
    return r;
}

/* sendmsg/recvmsg: flatten iovecs through one stack call (the Go stack
 * has no scatter/gather entry point). */
ssize_t sendmsg(int fd, const struct msghdr *msg, int flags) {
    if (!KL_IS_FAKE(fd))
        return real_sendmsg(fd, msg, flags);
    size_t total = 0;
    for (size_t i = 0; i < msg->msg_iovlen; i++) total += msg->msg_iov[i].iov_len;
    char *tmp = malloc(total ? total : 1);
    if (!tmp) { errno = ENOMEM; return -1; }
    size_t off = 0;
    for (size_t i = 0; i < msg->msg_iovlen; i++) {
        memcpy(tmp + off, msg->msg_iov[i].iov_base, msg->msg_iov[i].iov_len);
        off += msg->msg_iov[i].iov_len;
    }
    int r;
    if (msg->msg_name)
        r = go_sendto(fd, tmp, (int)total, flags,
                      msg->msg_name, (int)msg->msg_namelen);
    else
        r = go_send(fd, tmp, (int)total, flags);
    free(tmp);
    return r < 0 ? KL_FAIL() : r;
}
ssize_t recvmsg(int fd, struct msghdr *msg, int flags) {
    if (!KL_IS_FAKE(fd))
        return real_recvmsg(fd, msg, flags);
    size_t total = 0;
    for (size_t i = 0; i < msg->msg_iovlen; i++) total += msg->msg_iov[i].iov_len;
    char *tmp = malloc(total ? total : 1);
    if (!tmp) { errno = ENOMEM; return -1; }
    int r;
    if (msg->msg_name) {
        r = go_recvfrom(fd, tmp, (int)total, flags,
                        msg->msg_name, (int *)&msg->msg_namelen);
        if (r < 0 && klinikal_last_error() == EINVAL /* stream */) {
            r = go_recv(fd, tmp, (int)total, flags);
            if (r >= 0) {
                int al = (int)msg->msg_namelen;
                if (go_getpeername(fd, msg->msg_name, &al) == 0)
                    msg->msg_namelen = al;
            }
        }
    } else {
        r = go_recv(fd, tmp, (int)total, flags);
    }
    if (r < 0) { free(tmp); return KL_FAIL(); }
    int off = 0;
    for (size_t i = 0; i < msg->msg_iovlen && off < r; i++) {
        int c = r - off;
        if (c > (int)msg->msg_iov[i].iov_len) c = (int)msg->msg_iov[i].iov_len;
        memcpy(msg->msg_iov[i].iov_base, tmp + off, c);
        off += c;
    }
    free(tmp);
    return r;
}

/* ---- options / names: Linux numbers pass through unchanged ---- */
int setsockopt(int fd, int level, int optname, const void *optval, socklen_t optlen) {
    if (!KL_IS_FAKE(fd)) return real_setsockopt(fd, level, optname, optval, optlen);
    if (go_setsockopt(fd, level, optname, (void *)optval, (int)optlen) != 0)
        return KL_FAIL();
    return 0;
}

int getsockopt(int fd, int level, int optname, void *optval, socklen_t *optlen) {
    if (!KL_IS_FAKE(fd)) return real_getsockopt(fd, level, optname, optval, optlen);
    int len = (int)*optlen;
    if (go_getsockopt(fd, level, optname, optval, &len) != 0) return KL_FAIL();
    *optlen = (socklen_t)len;
    /* SO_ERROR already carries an errno value */
    return 0;
}

int getsockname(int fd, struct sockaddr *addr, socklen_t *len) {
    if (!KL_IS_FAKE(fd)) return real_getsockname(fd, addr, len);
    if (go_getsockname(fd, addr, (int *)len) != 0) return KL_FAIL();
    return 0;
}

int getpeername(int fd, struct sockaddr *addr, socklen_t *len) {
    if (!KL_IS_FAKE(fd)) return real_getpeername(fd, addr, len);
    if (go_getpeername(fd, addr, (int *)len) != 0) return KL_FAIL();
    return 0;
}

int shutdown(int fd, int how) {
    if (!KL_IS_FAKE(fd)) return real_shutdown(fd, how);
    if (go_shutdown(fd, how) != 0) return KL_FAIL();
    return 0;
}

/* ---- fcntl / ioctl: non-blocking is real (FIONBIO -> Go stack) ---- */
int fcntl(int fd, int cmd, ...) {
    long arg = 0;
    va_list ap;
    __builtin_va_start(ap, cmd);
    arg = __builtin_va_arg(ap, long);
    __builtin_va_end(ap);
    if (!KL_IS_FAKE(fd)) return real_fcntl(fd, cmd, arg);
    switch (cmd) {
    case F_GETFL: return O_RDWR | ((fd >= 0 && fd < KL_FD_MAX && kl_nb[fd]) ? O_NONBLOCK : 0);
    case F_SETFL: {
        int want = (arg & O_NONBLOCK) != 0;
        int cur = (fd < KL_FD_MAX) ? kl_nb[fd] : 0;
        if (!!want != !!cur) kl_set_nb(fd, want);
        return 0;
    }
    case F_SETFD: case F_GETFD: return 0;
    case F_DUPFD: case F_DUPFD_CLOEXEC: {
        /* CPython's os.dup lands here (fcntl F_DUPFD_CLOEXEC): allocate
         * a new fake fd aliasing this one; the Go side refcounts. */
        int n = kl_alloc_fd_from((int)arg);
        if (n < 0) return -1;
        if (go_dup(fd, n) != 0) {
            kl_release(n);
            real_close(n);
            return KL_FAIL();
        }
        kl_nb[n] = kl_nb[fd];
        if (cmd == F_DUPFD) real_fcntl(n, F_SETFD, 0); /* no CLOEXEC */
        return n;
    }
    default: errno = EINVAL; return -1;
    }
}

int ioctl(int fd, unsigned long request, ...) {
    void *arg = NULL;
    va_list ap;
    __builtin_va_start(ap, request);
    arg = __builtin_va_arg(ap, void *);
    __builtin_va_end(ap);
    if (!KL_IS_FAKE(fd)) return real_ioctl(fd, request, arg);
    if (request == FIONREAD) {
        if (go_ioctl(fd, FIONREAD, (unsigned int *)arg) != 0) return KL_FAIL();
        return 0;
    }
    if (request == FIONBIO) {
        kl_set_nb(fd, arg != NULL && *(int *)arg != 0);
        return 0;
    }
    errno = EINVAL;
    return -1;
}

/* ---- select / poll ----
 * The Go stack consumes glibc fd_set bitmaps and struct pollfd directly.
 * Only mixed real+tunnel sets need splitting: the two backends are each
 * probed non-blocking in 10ms slices (correct, if not elegant, for apps
 * that watch a tunnel fd and a pipe together). */
static int bitmap_has_real(const fd_set *bits, int nfds) {
    for (int fd = 0; fd < nfds; fd++)
        if (FD_ISSET(fd, bits) && !KL_IS_FAKE(fd)) return 1;
    return 0;
}
// fd_set bitmap helpers used by the select split: count ready entries,
// or restrict a set to only fake / only real fds for the per-backend
// pass.
static int bitmap_count(const fd_set *bits, int nfds) {
    int n = 0;
    for (int fd = 0; fd < nfds; fd++) if (FD_ISSET(fd, bits)) n++;
    return n;
}
static void bitmap_keep_fake(fd_set *bits, int nfds) {
    for (int fd = 0; fd < nfds; fd++)
        if (FD_ISSET(fd, bits) && !KL_IS_FAKE(fd)) FD_CLR(fd, bits);
}
static void bitmap_keep_real(fd_set *bits, int nfds) {
    for (int fd = 0; fd < nfds; fd++)
        if (FD_ISSET(fd, bits) && KL_IS_FAKE(fd)) FD_CLR(fd, bits);
}

/* Unified mixed-set wait: real fds are watched by the kernel directly;
 * each fake fd is represented by its eventfd bridge (go_start_notify,
 * idempotent per fd), so the whole wait blocks in ONE real poll() and
 * wakes on either backend — no slice polling. On an eventfd wake we
 * drain it, compute the fd's true revents via a zero-timeout go_poll,
 * and re-arm the eventfd when the fd is still ready (level-triggered).
 * Returns the ready count, 0 on timeout, -1 with errno (EINTR
 * propagates: POSIX poll/select may return EINTR), or -2 when some
 * fake fd has no bridge yet (connect in progress) so the caller can
 * fall back to slice polling for that call. */
static void eventfd_drain(int efd);
static void eventfd_arm(int efd);

/* drain an eventfd counter (EINTR-safe: a signal must not leave the
 * counter partially drained, or the level-triggered bridge spins) */
static void eventfd_drain(int efd) {
    uint64_t c;
    for (;;) {
        ssize_t r = read(efd, &c, 8);
        if (r == 8) continue;
        if (r < 0 && errno == EINTR) continue;
        break;
    }
}
/* re-arm (level-triggered keep-hot) */
static void eventfd_arm(int efd) {
    uint64_t one = 1;
    ssize_t r;
    do { r = write(efd, &one, 8); } while (r < 0 && errno == EINTR);
    (void)r;
}

static int kl_mux_wait(struct pollfd *fds, nfds_t n, int timeout_ms) {
    struct pollfd *comb = malloc(sizeof(struct pollfd) * (2 * n + 1));
    int *cidx = malloc(sizeof(int) * (2 * n + 1));
    if (!comb || !cidx) { free(comb); free(cidx); errno = ENOMEM; return -1; }
    for (nfds_t i = 0; i < n; i++) fds[i].revents = 0;
    struct timespec t0; clock_gettime(CLOCK_MONOTONIC, &t0);
    int ret = 0;
    for (;;) {
        nfds_t cn = 0;
        int bridged = 1;
        for (nfds_t i = 0; i < n && bridged; i++) {
            if (!KL_IS_FAKE(fds[i].fd)) {
                comb[cn] = (struct pollfd){fds[i].fd, fds[i].events, 0};
                cidx[cn++] = (int)i;
                continue;
            }
            int nfd = go_start_notify(fds[i].fd);
            if (nfd <= 0) { bridged = 0; break; }
            comb[cn] = (struct pollfd){nfd, POLLIN, 0};
            cidx[cn++] = (int)i;
        }
        if (!bridged) { ret = -2; break; }

        int remaining = timeout_ms;
        if (timeout_ms > 0) {
            struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
            long el = (ts.tv_sec - t0.tv_sec) * 1000 +
                      (ts.tv_nsec - t0.tv_nsec) / 1000000;
            remaining = timeout_ms - (int)el;
            if (remaining <= 0) { ret = 0; break; }
        }
        int r = real_poll(comb, cn, remaining);
        if (r < 0) { ret = -1; break; }   /* errno incl EINTR propagates */

        int got = 0;
        for (nfds_t k = 0; k < cn; k++) {
            int i = cidx[k];
            if (!KL_IS_FAKE(fds[i].fd)) {
                if (comb[k].revents) {
                    fds[i].revents |= comb[k].revents;
                    if (fds[i].revents) got++;
                }
                continue;
            }
            if (!(comb[k].revents & POLLIN)) continue;
            eventfd_drain(comb[k].fd);
            struct pollfd one = { fds[i].fd, fds[i].events, 0 };
            go_poll(&one, 1, 0);
            if (one.revents) {
                fds[i].revents |= one.revents;
                got++;
                if (one.revents & fds[i].events) eventfd_arm(comb[k].fd);
            }
        }
        if (got > 0) { ret = got; break; }
        if (r == 0) { ret = 0; break; }    /* timed out */
        /* spurious wake: loop with the remaining time */
    }
    free(comb); free(cidx);
    return ret;
}

static int select_slice(int nfds, fd_set *readfds, fd_set *writefds,
                        fd_set *exceptfds, struct timeval *timeout);
int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
           struct timeval *timeout) {
    int has_real = 0, has_fake = 0;
    if (readfds)  { has_real |= bitmap_has_real(readfds, nfds);  has_fake |= bitmap_count(readfds, nfds) > 0; }
    if (writefds) { has_real |= bitmap_has_real(writefds, nfds); has_fake |= bitmap_count(writefds, nfds) > 0; }
    if (!has_fake) return real_select(nfds, readfds, writefds, exceptfds, timeout);

    if (!has_real) {
        /* all tunnel fds: straight pass-through, Go updates the sets */
        int rc = go_select(nfds, readfds, writefds, exceptfds, timeout);
        if (rc < 0) return KL_FAIL();
        return rc;
    }

    /* mixed: unified bridge wait over read/write sets; exceptfds is a
     * real-backend concern (OOB), probed non-blocking as before */
    struct pollfd *pf = malloc(sizeof(struct pollfd) * (size_t)nfds * 2);
    if (!pf) { errno = ENOMEM; return -1; }
    int *pidx = malloc(sizeof(int) * (size_t)nfds * 2);
    if (!pidx) { free(pf); errno = ENOMEM; return -1; }
    nfds_t pn = 0;
    for (int fd = 0; fd < nfds; fd++) {
        short ev = 0;
        if (readfds && FD_ISSET(fd, readfds)) ev |= POLLIN;
        if (writefds && FD_ISSET(fd, writefds)) ev |= POLLOUT;
        if (ev) { pf[pn] = (struct pollfd){fd, ev, 0}; pidx[pn++] = fd; }
    }
    int ms = -1;
    if (timeout) ms = (int)(timeout->tv_sec * 1000 +
                            (timeout->tv_usec + 999) / 1000);
    int m = kl_mux_wait(pf, pn, ms);
    if (m == -2) {
        /* unbridgeable fd: fall back to slice alternation */
        free(pf); free(pidx);
        return select_slice(nfds, readfds, writefds, exceptfds, timeout);
    }
    if (m < 0) { free(pf); free(pidx); return -1; }  /* errno set */
    if (readfds) FD_ZERO(readfds);
    if (writefds) FD_ZERO(writefds);
    if (exceptfds) FD_ZERO(exceptfds);
    int got = 0;
    for (nfds_t k = 0; k < pn; k++) {
        if (!pf[k].revents) continue;
        if (readfds && (pf[k].revents & (POLLIN | POLLHUP | POLLERR))) {
            FD_SET(pidx[k], readfds); got++;
        } else if (writefds && (pf[k].revents & (POLLOUT | POLLHUP | POLLERR))) {
            FD_SET(pidx[k], writefds); got++;
        }
    }
    /* except: real-backend OOB probe, non-blocking */
    if (exceptfds && bitmap_count(exceptfds, nfds) > 0) {
        fd_set re = *exceptfds;
        int rrc = real_select(nfds, NULL, NULL, &re, &(struct timeval){0, 0});
        if (rrc > 0) {
            for (int fd = 0; fd < nfds; fd++)
                if (FD_ISSET(fd, &re)) { FD_SET(fd, exceptfds); got++; }
        }
    }
    free(pf); free(pidx);
    return got;
}

/* legacy slice alternation, used only when a fake fd has no eventfd
 * bridge yet (connect in progress): alternate non-blocking probes of the
 * tunnel side and the real side on a 10ms cadence, POSIX set semantics
 * (caller sets modified only for ready fds). */
static int select_slice(int nfds, fd_set *readfds, fd_set *writefds,
                        fd_set *exceptfds, struct timeval *timeout) {
    struct timespec t0; clock_gettime(CLOCK_MONOTONIC, &t0);
    while (1) {
        fd_set tr = {0}, tw = {0}, tx = {0}, *trp = NULL, *twp = NULL, *txp = NULL;
        if (readfds)  { tr = *readfds;  trp = &tr; }
        if (writefds) { tw = *writefds; twp = &tw; }
        if (exceptfds){ tx = *exceptfds; txp = &tx; }
        struct timeval zero = {0, 0};
        int rc = go_select(nfds, trp, twp, txp, &zero);
        (void)rc;
        fd_set or_ = {0}, ow = {0}, ox = {0};
        if (trp) or_ = tr;
        if (twp) ow = tw;
        if (txp) ox = tx;
        /* real side, non-blocking */
        fd_set rr = {0}, rw = {0}, rx = {0}, *rrp = NULL, *rwp = NULL, *rxp = NULL;
        if (readfds)  { rrp = &rr; }
        if (writefds) { rwp = &rw; }
        if (exceptfds){ rxp = &rx; }
        real_select(nfds, rrp, rwp, rxp, &zero);
        if (rrp) for (int fd = 0; fd < nfds; fd++) if (FD_ISSET(fd, &rr)) FD_SET(fd, &or_);
        if (rwp) for (int fd = 0; fd < nfds; fd++) if (FD_ISSET(fd, &rw)) FD_SET(fd, &ow);
        if (rxp) for (int fd = 0; fd < nfds; fd++) if (FD_ISSET(fd, &rx)) FD_SET(fd, &ox);
        int got = 0;
        if (readfds)  *readfds  = or_;
        if (writefds) *writefds = ow;
        if (exceptfds)*exceptfds= ox;
        for (int fd = 0; fd < nfds; fd++) {
            if (readfds && FD_ISSET(fd, &or_)) got++;
            if (writefds && FD_ISSET(fd, &ow)) got++;
            if (exceptfds && FD_ISSET(fd, &ox)) got++;
        }
        if (got > 0) return got;
        if (timeout && timeout->tv_sec == 0 && timeout->tv_usec == 0) return 0;
        if (timeout) {
            struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
            long elapsed_us = (ts.tv_sec - t0.tv_sec) * 1000000L +
                              (ts.tv_nsec - t0.tv_nsec) / 1000L;
            long want = timeout->tv_sec * 1000000L + timeout->tv_usec;
            if (elapsed_us >= want) return 0;
        }
        struct timespec slice = {0, 10 * 1000 * 1000}; nanosleep(&slice, NULL);
    }
}


/* poll: all-fake -> go_poll (native pollfd pass-through); all-real ->
 * libc; mixed -> kl_mux_wait (eventfd bridge, blocks in one kernel
 * poll); slice loop only when an fd has no bridge yet. */
int poll(struct pollfd *fds, nfds_t n, int timeout_ms) {
    int has_real = 0, has_fake = 0;
    for (nfds_t i = 0; i < n; i++)
        if (KL_IS_FAKE(fds[i].fd)) has_fake = 1; else has_real = 1;
    if (!has_fake) return real_poll(fds, n, timeout_ms);

    if (!has_real) {
        int rc = go_poll(fds, (int)n, timeout_ms);
        if (rc < 0) return KL_FAIL();
        return rc;
    }

    int m = kl_mux_wait(fds, n, timeout_ms);
    if (m >= -1) return m;   /* -1 keeps errno from the real poll */
    /* -2: an fd has no bridge yet (connect in progress): slice loop */
    struct timespec t0; clock_gettime(CLOCK_MONOTONIC, &t0);
    while (1) {
        int got = 0;
        /* fake entries, non-blocking, in one go_poll call */
        struct pollfd sub[64];
        nfds_t sub_idx[64];
        nfds_t sn = 0;
        for (nfds_t i = 0; i < n; i++) {
            fds[i].revents = 0;
            if (!KL_IS_FAKE(fds[i].fd)) continue;
            if (sn < 64) {
                sub[sn] = (struct pollfd){fds[i].fd, fds[i].events, 0};
                sub_idx[sn++] = i;
            }
        }
        if (sn > 0) {
            go_poll(sub, (int)sn, 0);
            for (nfds_t k = 0; k < sn; k++)
                if (sub[k].revents) { fds[sub_idx[k]].revents = sub[k].revents; got++; }
        }
        /* real entries, non-blocking */
        for (nfds_t i = 0; i < n; i++) {
            if (KL_IS_FAKE(fds[i].fd)) continue;
            struct pollfd one = { fds[i].fd, fds[i].events, 0 };
            int rr = real_poll(&one, 1, 0);
            if (rr > 0) { fds[i].revents = one.revents; got++; }
        }
        if (got > 0) return got;
        if (timeout_ms == 0) return 0;
        struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
        long elapsed = (ts.tv_sec - t0.tv_sec) * 1000 +
                       (ts.tv_nsec - t0.tv_nsec) / 1000000;
        if (timeout_ms > 0 && elapsed >= timeout_ms) return 0;
        struct timespec slice = {0, 10 * 1000 * 1000}; nanosleep(&slice, NULL);
    }
}

/* ppoll/pselect: CPython's connect-wait and selectors use these */
int ppoll(struct pollfd *fds, nfds_t n, const struct timespec *tmo_p,
          const sigset_t *sigmask) {
    (void)sigmask; /* signal mask swap not emulated */
    int ms = -1;
    if (tmo_p) ms = (int)(tmo_p->tv_sec * 1000 + tmo_p->tv_nsec / 1000000);
    return poll(fds, n, ms);
}

int pselect(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
            const struct timespec *timeout, const sigset_t *sigmask) {
    (void)sigmask;
    struct timeval tv, *tvp = NULL;
    if (timeout) {
        tv.tv_sec = timeout->tv_sec;
        tv.tv_usec = timeout->tv_nsec / 1000;
        tvp = &tv;
    }
    return select(nfds, readfds, writefds, exceptfds, tvp);
}

/* ---- epoll via eventfd bridge ----
 * Each registered tunnel fd gets an eventfd from the Go stack (created
 * on demand; the stack's gvisor waiter signals it on state changes).
 * That eventfd is added to the real kernel epoll, so epoll_wait blocks
 * in the kernel and wakes exactly on activity. After a wake we drain the
 * eventfd, compute real revents via poll(0), and re-arm the eventfd if
 * the fd is still ready (level-triggered semantics). Entries whose
 * eventfd is not available yet (connect in progress) are retried
 * lazily; if any remain we fall back to 10ms slicing for that call. */
struct kl_ep { int epfd; int fd; uint32_t events; epoll_data_t data; int used; int notify_fd; };
#define KL_EP_MAX 1024
static struct kl_ep kl_ep_tbl[KL_EP_MAX];
/* kl_ep_tbl is mutated from epoll_ctl/epoll_wait/close/dup2 and may be
 * touched concurrently from different app threads; all table walks and
 * mutations run under kl_tbl_mu (never held across a blocking wait). */
/* internal registrations carry data.u64 in this token range; an app's own
 * data values are passed through untouched (a real app value colliding
 * with the token range is checked against table liveness before use) */
#define KL_EP_TOKEN_BASE 0x0BAD0000ull
/* drop all registrations for an fd (called on close/dup2-overwrite) */
/* caller holds kl_tbl_mu */
static void kl_ep_purge_locked(int fd) {
    for (int i = 0; i < KL_EP_MAX; i++)
        if (kl_ep_tbl[i].used && kl_ep_tbl[i].fd == fd)
            kl_ep_tbl[i].used = 0; /* eventfd closed by Go side; epoll auto-removes */
}
/* self-locking variant for call sites outside the table lock */
void kl_ep_purge_fd_fwd(int fd) {
    pthread_mutex_lock(&kl_tbl_mu);
    kl_ep_purge_locked(fd);
    pthread_mutex_unlock(&kl_tbl_mu);
}

/* caller holds kl_tbl_mu */
static int kl_ep_add(int epfd, int fd, struct epoll_event *ev) {
    for (int i = 0; i < KL_EP_MAX; i++) {
        if (!kl_ep_tbl[i].used) {
            kl_ep_tbl[i] = (struct kl_ep){epfd, fd,
                ev ? ev->events : 0, ev ? ev->data : (epoll_data_t){0}, 1, 0};
            int nfd = go_start_notify(fd);
            if (nfd > 0) {
                kl_ep_tbl[i].notify_fd = nfd;
                struct epoll_event nev;
                nev.events = ev ? ev->events : 0;
                nev.data.u64 = KL_EP_TOKEN_BASE + (uint64_t)i;
                real_epoll_ctl(epfd, EPOLL_CTL_ADD, nfd, &nev);
                if (getenv("KLINIKAL_VERBOSE"))
                    fprintf(stderr, "kl: epoll bridged fd=%d via eventfd=%d\n", fd, nfd);
            } else if (getenv("KLINIKAL_VERBOSE")) {
                fprintf(stderr, "kl: epoll fd=%d unbridged (no waiter queue yet)\n", fd);
            }
            return 0;
        }
    }
    errno = ENOSPC; return -1;
}

/* caller holds kl_tbl_mu */
static struct kl_ep *kl_ep_find(int epfd, int fd) {
    for (int i = 0; i < KL_EP_MAX; i++)
        if (kl_ep_tbl[i].used && kl_ep_tbl[i].epfd == epfd && kl_ep_tbl[i].fd == fd)
            return &kl_ep_tbl[i];
    return NULL;
}

int epoll_create(int size) { return epoll_create1(0); }
int epoll_create1(int flags) {
    kl_ensure();
    int e = real_epoll_create1(flags);
    if (getenv("KLINIKAL_VERBOSE"))
        fprintf(stderr, "kl: epoll_create1 -> epfd=%d (fake[%d]=%d)\n",
                e, e < KL_FD_MAX ? e : -1, e < KL_FD_MAX ? kl_fake[e] : -1);
    return e;
}

int epoll_ctl(int epfd, int op, int fd, struct epoll_event *ev) {
    if (!KL_IS_FAKE(fd)) return real_epoll_ctl(epfd, op, fd, ev);
    pthread_mutex_lock(&kl_tbl_mu);
    struct kl_ep *e = kl_ep_find(epfd, fd);
    if (op == EPOLL_CTL_ADD) {
        if (e) { pthread_mutex_unlock(&kl_tbl_mu); errno = EEXIST; return -1; }
        int r = kl_ep_add(epfd, fd, ev);
        pthread_mutex_unlock(&kl_tbl_mu);
        return r;
    }
    if (op == EPOLL_CTL_MOD) {
        if (!e) { pthread_mutex_unlock(&kl_tbl_mu); errno = ENOENT; return -1; }
        if (ev) {
            e->events = ev->events; e->data = ev->data;
            if (e->notify_fd > 0) {
                struct epoll_event nev;
                nev.events = ev->events;
                nev.data.u64 = KL_EP_TOKEN_BASE + (uint64_t)(e - kl_ep_tbl);
                real_epoll_ctl(epfd, EPOLL_CTL_MOD, e->notify_fd, &nev);
            }
        }
        pthread_mutex_unlock(&kl_tbl_mu);
        return 0;
    }
    if (op == EPOLL_CTL_DEL) {
        if (!e) { pthread_mutex_unlock(&kl_tbl_mu); errno = ENOENT; return -1; }
        if (e->notify_fd > 0) real_epoll_ctl(epfd, EPOLL_CTL_DEL, e->notify_fd, NULL);
        e->used = 0;
        pthread_mutex_unlock(&kl_tbl_mu);
        return 0;
    }
    pthread_mutex_unlock(&kl_tbl_mu);
    errno = EINVAL; return -1;
}

/* one fake fd's current revents via non-blocking poll */
static short fake_revents(int fd, uint32_t events) {
    struct pollfd pf = { fd, (short)events, 0 };
    go_poll(&pf, 1, 0);
    return pf.revents;
}

int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout) {
    int fake_n = 0, unbridged = 0;
    pthread_mutex_lock(&kl_tbl_mu);
    for (int i = 0; i < KL_EP_MAX; i++) {
        if (!kl_ep_tbl[i].used || kl_ep_tbl[i].epfd != epfd) continue;
        if (!KL_IS_FAKE(kl_ep_tbl[i].fd)) { kl_ep_tbl[i].used = 0; continue; }
        fake_n++;
        if (kl_ep_tbl[i].notify_fd == 0) {
            /* connect may have completed since ADD: try bridging now */
            int nfd = go_start_notify(kl_ep_tbl[i].fd);
            if (nfd > 0) {
                kl_ep_tbl[i].notify_fd = nfd;
                struct epoll_event nev;
                nev.events = kl_ep_tbl[i].events;
                nev.data.u64 = KL_EP_TOKEN_BASE + (uint64_t)i;
                real_epoll_ctl(epfd, EPOLL_CTL_ADD, nfd, &nev);
            } else {
                unbridged++;
            }
        }
    }
    pthread_mutex_unlock(&kl_tbl_mu);
    if (!fake_n) return real_epoll_wait(epfd, events, maxevents, timeout);

    if (!unbridged) {
        /* fully event-driven: block in the kernel epoll */
        struct timespec t0; clock_gettime(CLOCK_MONOTONIC, &t0);
        int remaining = timeout;
        for (;;) {
            int n = real_epoll_wait(epfd, events, maxevents, remaining);
            if (n == 0) return 0;             /* timed out */
            if (n < 0) {
                if (getenv("KLINIKAL_VERBOSE")) {
                    int fl = real_fcntl(epfd, F_GETFD);
                    fprintf(stderr, "kl: epoll_wait EINVAL/err on epfd=%d errno=%d fcntl=%d\n",
                            epfd, errno, fl);
                }
                return -1;             /* intr/err */
            }
            int out = 0;
            for (int i = 0; i < n; i++) {
                uint64_t d = events[i].data.u64;
                struct kl_ep *e = NULL;
                if (d >= KL_EP_TOKEN_BASE && d < KL_EP_TOKEN_BASE + KL_EP_MAX) {
                    pthread_mutex_lock(&kl_tbl_mu);
                    struct kl_ep *cand = &kl_ep_tbl[d - KL_EP_TOKEN_BASE];
                    if (cand->used && cand->epfd == epfd) e = cand;
                    pthread_mutex_unlock(&kl_tbl_mu);
                }
                if (e) {
                    eventfd_drain(e->notify_fd);
                    short rv = fake_revents(e->fd, e->events);
                    if (rv) {
                        events[out].events = (uint32_t)rv;
                        events[out].data = e->data;
                        out++;
                        eventfd_arm(e->notify_fd); /* level-triggered */
                    }
                } else {
                    events[out++] = events[i]; /* real fd */
                }
            }
            if (out > 0) return out;
            if (timeout < 0) continue; /* infinite wait, spurious wake */
            struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
            long used_ms = (ts.tv_sec - t0.tv_sec) * 1000 +
                           (ts.tv_nsec - t0.tv_nsec) / 1000000;
            remaining = timeout - (int)used_ms;
            if (remaining <= 0) return 0;
        }
    }

    /* some entries unbridgeable (connect in progress): slice loop */
    if (getenv("KLINIKAL_VERBOSE"))
        fprintf(stderr, "kl: epoll_wait slice fallback (unbridged=%d)\n", unbridged);
    struct timespec t0; clock_gettime(CLOCK_MONOTONIC, &t0);
    while (1) {
        int got = 0;
        pthread_mutex_lock(&kl_tbl_mu);
        for (int i = 0; i < KL_EP_MAX && got < maxevents; i++) {
            if (!kl_ep_tbl[i].used || kl_ep_tbl[i].epfd != epfd) continue;
            struct kl_ep *ent = &kl_ep_tbl[i];
            pthread_mutex_unlock(&kl_tbl_mu);
            short rv = fake_revents(ent->fd, ent->events);
            pthread_mutex_lock(&kl_tbl_mu);
            if (rv && ent->used) {
                events[got].events = (uint32_t)rv;
                events[got].data = ent->data;
                got++;
            }
        }
        pthread_mutex_unlock(&kl_tbl_mu);
        if (got < maxevents) {
            struct epoll_event rev[64];
            int rr = real_epoll_wait(epfd, rev,
                        maxevents - got < 64 ? maxevents - got : 64, 0);
            for (int i = 0; i < rr && got < maxevents; i++) {
                uint64_t d = rev[i].data.u64;
                if (d >= KL_EP_TOKEN_BASE && d < KL_EP_TOKEN_BASE + KL_EP_MAX)
                    continue; /* bridged fake entry: handled by the poll loop above */
                events[got++] = rev[i];
            }
        }
        if (got > 0) return got;
        if (timeout == 0) return 0;
        struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
        long elapsed_ms = (ts.tv_sec - t0.tv_sec) * 1000 +
                          (ts.tv_nsec - t0.tv_nsec) / 1000000;
        if (timeout > 0 && elapsed_ms >= timeout) return 0;
        struct timespec slice = {0, 10 * 1000 * 1000}; nanosleep(&slice, NULL);
    }
}

int epoll_pwait(int epfd, struct epoll_event *events, int maxevents,
                int timeout, const sigset_t *sigmask) {
    (void)sigmask; /* signal mask switching not emulated */
    return epoll_wait(epfd, events, maxevents, timeout);
}

/* ---- name resolution over the tunnel ----
 * The Go stack writes glibc-layout addrinfo chains directly (Linux AF
 * values, socklen_t addrlen, glibc EAI codes); the loader passes the
 * chain through untouched and asks the Go side authoritatively on
 * freeaddrinfo which chains it owns. */
int getaddrinfo(const char *node, const char *service,
                const struct addrinfo *hints, struct addrinfo **res) {
    void *gres = NULL;
    int rc = go_getaddrinfo((char *)node, (char *)service,
                            (void *)hints, &gres);
    if (rc != 0 || !gres) return rc ? rc : EAI_NONAME;
    *res = (struct addrinfo *)gres;
    return 0;
}

void freeaddrinfo(struct addrinfo *res) {
    /* the Go side knows authoritatively which chains it allocated */
    if (go_addrinfo_owned((void *)res)) {
        go_freeaddrinfo((void *)res);
        return;
    }
    real_freeaddrinfo(res);
}
