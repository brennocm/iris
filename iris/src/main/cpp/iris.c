/*
 * Native probes for iris.
 *
 * Every file and directory access here goes straight to the kernel. On arm64 and x86_64 the
 * syscall instruction is issued inline, so hooking libc (open, read, strstr, syscall) with
 * Frida or an LD_PRELOAD-style shim does not change what these functions see. On 32-bit ABIs
 * the libc syscall() wrapper is used; see docs/adr/0003-direct-syscalls.md.
 */
#include <jni.h>

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#if defined(__aarch64__)
static long raw_syscall4(long n, long a0, long a1, long a2, long a3) {
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    __asm__ volatile("svc #0"
                     : "+r"(x0)
                     : "r"(x8), "r"(x1), "r"(x2), "r"(x3)
                     : "memory", "cc");
    return x0; /* -errno on failure */
}
#elif defined(__x86_64__)
static long raw_syscall4(long n, long a0, long a1, long a2, long a3) {
    long ret;
    register long r10 __asm__("r10") = a3;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"(n), "D"(a0), "S"(a1), "d"(a2), "r"(r10)
                     : "rcx", "r11", "memory");
    return ret; /* -errno on failure */
}
#else
static long raw_syscall4(long n, long a0, long a1, long a2, long a3) {
    long ret = syscall(n, a0, a1, a2, a3);
    return ret < 0 ? -errno : ret;
}
#endif

static int sys_openat(const char *path, int flags) {
    return (int)raw_syscall4(__NR_openat, AT_FDCWD, (long)path, flags, 0);
}

static long sys_read(int fd, void *buf, size_t len) {
    long r;
    do {
        r = raw_syscall4(__NR_read, fd, (long)buf, (long)len, 0);
    } while (r == -EINTR);
    return r;
}

static void sys_close(int fd) { raw_syscall4(__NR_close, fd, 0, 0, 0); }

static int sys_faccessat(const char *path) {
    return (int)raw_syscall4(__NR_faccessat, AT_FDCWD, (long)path, F_OK, 0);
}

static long sys_getdents64(int fd, void *buf, size_t len) {
    return raw_syscall4(__NR_getdents64, fd, (long)buf, (long)len, 0);
}

/* Reads up to max bytes of path into a malloc'd buffer. Returns NULL if it cannot be opened. */
static char *read_all(const char *path, size_t max, size_t *out_len) {
    int fd = sys_openat(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return NULL;
    size_t cap = 16 * 1024, len = 0;
    char *buf = malloc(cap);
    while (buf != NULL && len < max) {
        if (len == cap) {
            size_t next = cap * 2 > max ? max : cap * 2;
            char *grown = realloc(buf, next);
            if (grown == NULL) {
                free(buf);
                buf = NULL;
                break;
            }
            buf = grown;
            cap = next;
        }
        long n = sys_read(fd, buf + len, cap - len);
        if (n < 0) {
            free(buf);
            buf = NULL;
        } else if (n == 0) {
            break;
        } else {
            len += (size_t)n;
        }
    }
    sys_close(fd);
    *out_len = len;
    return buf;
}

JNIEXPORT jbyteArray JNICALL
Java_io_github_brennocm_iris_NativeProbes_readFile(JNIEnv *env, jclass clazz, jstring jpath,
                                                       jint max_bytes) {
    (void)clazz;
    if (jpath == NULL || max_bytes <= 0) return NULL;
    const char *path = (*env)->GetStringUTFChars(env, jpath, NULL);
    if (path == NULL) return NULL;
    size_t len = 0;
    char *data = read_all(path, (size_t)max_bytes, &len);
    (*env)->ReleaseStringUTFChars(env, jpath, path);
    if (data == NULL) return NULL;
    jbyteArray out = (*env)->NewByteArray(env, (jsize)len);
    if (out != NULL) (*env)->SetByteArrayRegion(env, out, 0, (jsize)len, (const jbyte *)data);
    free(data);
    return out;
}

JNIEXPORT jint JNICALL
Java_io_github_brennocm_iris_NativeProbes_access(JNIEnv *env, jclass clazz, jstring jpath) {
    (void)clazz;
    if (jpath == NULL) return -EINVAL;
    const char *path = (*env)->GetStringUTFChars(env, jpath, NULL);
    if (path == NULL) return -ENOMEM;
    int r = sys_faccessat(path);
    (*env)->ReleaseStringUTFChars(env, jpath, path);
    return r;
}

struct pal_dirent64 {
    uint64_t d_ino;
    int64_t d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[];
};

#define MAX_THREADS 65536 /* beyond this the list is reported as unreadable, not truncated */
#define COMM_LEN 16       /* TASK_COMM_LEN, including the terminator */

JNIEXPORT jobjectArray JNICALL
Java_io_github_brennocm_iris_NativeProbes_threadNames(JNIEnv *env, jclass clazz) {
    (void)clazz;
    int dir = sys_openat("/proc/self/task", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dir < 0) return NULL;

    int cap = 256, count = 0, failed = 0;
    char (*names)[COMM_LEN] = calloc((size_t)cap, COMM_LEN);
    char dents[4096];
    while (names != NULL && !failed) {
        long n = sys_getdents64(dir, dents, sizeof dents);
        if (n < 0) failed = 1;
        if (n <= 0) break;
        for (long pos = 0; pos < n && !failed;) {
            struct pal_dirent64 *d = (struct pal_dirent64 *)(dents + pos);
            pos += d->d_reclen;
            if (d->d_name[0] < '0' || d->d_name[0] > '9') continue; /* skip . and .. */
            if (count == cap) {
                /* A truncated list could hide the agent's threads, so too many is a failure. */
                if (cap >= MAX_THREADS) {
                    failed = 1;
                    break;
                }
                char (*grown)[COMM_LEN] = realloc(names, (size_t)cap * 2 * COMM_LEN);
                if (grown == NULL) {
                    failed = 1;
                    break;
                }
                memset(grown + cap, 0, (size_t)cap * COMM_LEN);
                names = grown;
                cap *= 2;
            }
            char path[64];
            size_t used = strlen("/proc/self/task/");
            size_t nl = strnlen(d->d_name, sizeof path - used - sizeof "/comm");
            memcpy(path, "/proc/self/task/", used);
            memcpy(path + used, d->d_name, nl);
            memcpy(path + used + nl, "/comm", sizeof "/comm");
            size_t len = 0;
            char *comm = read_all(path, COMM_LEN, &len); /* thread may have exited: skip it */
            if (comm == NULL) continue;
            for (size_t i = 0; i < len && i < COMM_LEN - 1; i++) {
                char c = comm[i];
                if (c == '\n') break;
                /* comm is arbitrary bytes; keep NewStringUTF's input valid ASCII */
                names[count][i] = (c >= 0x20 && c < 0x7f) ? c : '?';
            }
            free(comm);
            count++;
        }
    }
    sys_close(dir);

    if (names == NULL) return NULL;
    jobjectArray out = NULL;
    jclass string_class = failed ? NULL : (*env)->FindClass(env, "java/lang/String");
    if (string_class != NULL) out = (*env)->NewObjectArray(env, count, string_class, NULL);
    for (int i = 0; out != NULL && i < count; i++) {
        jstring s = (*env)->NewStringUTF(env, names[i]);
        if (s == NULL) {
            out = NULL;
            break;
        }
        (*env)->SetObjectArrayElement(env, out, i, s);
        (*env)->DeleteLocalRef(env, s);
    }
    free(names);
    return out;
}

/*
 * Loopback connect to port, for the frida-server check when /proc/net/tcp is denied.
 * Returns 0 when something accepts the connection, otherwise the negated errno.
 */
JNIEXPORT jint JNICALL
Java_io_github_brennocm_iris_NativeProbes_connectLoopback(JNIEnv *env, jclass clazz, jint port) {
    (void)env;
    (void)clazz;
    if (port <= 0 || port > 65535) return -EINVAL;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
#if defined(__aarch64__) || defined(__x86_64__)
    int fd = (int)raw_syscall4(__NR_socket, AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0, 0);
    if (fd < 0) return fd;
    long r;
    do {
        r = raw_syscall4(__NR_connect, fd, (long)&addr, sizeof addr, 0);
    } while (r == -EINTR);
    sys_close(fd);
    return (jint)r;
#else
    /* 32-bit x86 only gained direct socket syscalls in Linux 4.3; libc's socketcall works everywhere. */
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -errno;
    int r = connect(fd, (struct sockaddr *)&addr, sizeof addr);
    int err = r < 0 ? -errno : 0;
    close(fd);
    return err;
#endif
}

/*
 * Reads length bytes of this process's memory at address through /proc/self/mem, so an
 * unmapped or protected address gives an error instead of a crash. Returns NULL on failure.
 */
JNIEXPORT jbyteArray JNICALL
Java_io_github_brennocm_iris_NativeProbes_readMemory(JNIEnv *env, jclass clazz, jlong address,
                                                         jint length) {
    (void)clazz;
    if (length <= 0 || length > 4096 || address <= 0) return NULL;
    unsigned char buf[4096];
    int fd = sys_openat("/proc/self/mem", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return NULL;
    long got = 0;
    while (got < length) {
#if defined(__aarch64__) || defined(__x86_64__)
        long n = raw_syscall4(__NR_pread64, fd, (long)(buf + got), length - got, (long)(address + got));
        if (n == -EINTR) continue;
#else
        long n = pread64(fd, buf + got, (size_t)(length - got), (off64_t)(uintptr_t)(address + got));
        if (n < 0 && errno == EINTR) continue;
#endif
        if (n <= 0) break;
        got += n;
    }
    sys_close(fd);
    if (got != length) return NULL;
    jbyteArray out = (*env)->NewByteArray(env, length);
    if (out != NULL) (*env)->SetByteArrayRegion(env, out, 0, length, (const jbyte *)buf);
    return out;
}
