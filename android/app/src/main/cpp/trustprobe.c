/*
 * Native integrity probes (catalogue F039/F040, F146-F157, F159, F163, F210, F213, F219, F220, F360, F368).
 *
 * Everything is measured from inside the process and returned as one JSON string; the Kotlin
 * side (NativeProbes.kt) turns it into catalogue signals. Nothing here decides risk: it reports
 * facts (bytes that differ, results that disagree, latencies).
 *
 * Techniques:
 *  - Raw syscalls (svc #0 on arm64) bypass libc, so a libc hook that hides root files shows up
 *    as a disagreement between access() and the raw faccessat.
 *  - Prologue / text checks compare code in memory with the same bytes in the file it was
 *    mapped from (path + offset from /proc/self/maps). Inline hooks patch memory, not the file.
 *  - GOT check: &open as seen through this library's GOT must equal dlsym(libc, "open").
 *  - JNI table: every JNIEnv function pointer must point into libart.
 */
#include <jni.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define EXPORT __attribute__((visibility("default")))

/* ---------- raw syscalls ---------- */

static long raw_syscall4(long n, long a, long b, long c, long d) {
#if defined(__aarch64__)
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    register long x3 __asm__("x3") = d;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2), "r"(x3) : "memory", "cc");
    return x0;
#elif defined(__x86_64__)
    long ret;
    register long r10 __asm__("r10") = d;
    __asm__ volatile("syscall" : "=a"(ret) : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10) : "rcx", "r11", "memory");
    return ret;
#else
    long r = syscall(n, a, b, c, d);
    return r < 0 ? -errno : r;
#endif
}

static int raw_exists(const char *path) {
    return raw_syscall4(__NR_faccessat, AT_FDCWD, (long) path, F_OK, 0) == 0;
}

/* ---------- JSON builder ---------- */

typedef struct { char *buf; size_t len, cap; } sb_t;

static void sb_add(sb_t *s, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
#include <stdarg.h>
static void sb_add(sb_t *s, const char *fmt, ...) {
    for (;;) {
        va_list ap;
        va_start(ap, fmt);
        int n = vsnprintf(s->buf + s->len, s->cap - s->len, fmt, ap);
        va_end(ap);
        if (n < 0) return;
        if (s->len + (size_t) n < s->cap) { s->len += (size_t) n; return; }
        size_t cap = s->cap * 2 + (size_t) n;
        char *nb = realloc(s->buf, cap);
        if (!nb) return;
        s->buf = nb;
        s->cap = cap;
    }
}

/* JSON string escaping for paths (quotes, backslashes, control chars). */
static void sb_str(sb_t *s, const char *v) {
    sb_add(s, "\"");
    for (const char *p = v; p && *p; p++) {
        unsigned char c = (unsigned char) *p;
        if (c == '"' || c == '\\') sb_add(s, "\\%c", c);
        else if (c < 0x20) sb_add(s, "\\u%04x", c);
        else sb_add(s, "%c", c);
    }
    sb_add(s, "\"");
}

/* ---------- /proc/self/maps lookup ---------- */

typedef struct {
    uintptr_t start, end;
    unsigned long long offset;
    char perms[5];
    char path[512];
} mapping_t;

/* Finds the mapping containing addr. Returns 1 on success. */
static int find_mapping(uintptr_t addr, mapping_t *out) {
    FILE *f = fopen("/proc/self/maps", "re");
    if (!f) return 0;
    char line[1024];
    int found = 0;
    while (fgets(line, sizeof line, f)) {
        mapping_t m;
        memset(&m, 0, sizeof m);
        int pos = 0;
        if (sscanf(line, "%lx-%lx %4s %llx %*s %*s %n", (unsigned long *) &m.start, (unsigned long *) &m.end,
                   m.perms, &m.offset, &pos) < 4) continue;
        if (addr < m.start || addr >= m.end) continue;
        char *p = line + pos;
        size_t l = strcspn(p, "\n");
        if (l >= sizeof m.path) l = sizeof m.path - 1;
        memcpy(m.path, p, l);
        m.path[l] = 0;
        *out = m;
        found = 1;
        break;
    }
    fclose(f);
    return found;
}

/*
 * Compares len bytes of code at addr with the file it is mapped from.
 * Returns the number of differing bytes, or -1 if memory or file cannot be read.
 */
static long diff_with_file(uintptr_t addr, size_t len) {
    mapping_t m;
    if (!find_mapping(addr, &m) || m.perms[0] != 'r' || m.path[0] != '/') return -1;
    if (strstr(m.path, "(deleted)")) return -1;
    if (addr + len > m.end) len = m.end - addr;
    int fd = open(m.path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    unsigned char *file = malloc(len);
    if (!file) { close(fd); return -1; }
    ssize_t got = pread(fd, file, len, (off_t) (m.offset + (addr - m.start)));
    close(fd);
    if (got != (ssize_t) len) { free(file); return -1; }
    const unsigned char *mem = (const unsigned char *) addr;
    long diff = 0;
    for (size_t i = 0; i < len; i++) if (mem[i] != file[i]) diff++;
    free(file);
    return diff;
}

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t) ts.tv_sec * 1000000000ull + (uint64_t) ts.tv_nsec;
}

static int cmp_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *) a, y = *(const uint64_t *) b;
    return x < y ? -1 : x > y;
}

#define TRIALS 64
static uint64_t median(uint64_t *v) {
    qsort(v, TRIALS, sizeof *v, cmp_u64);
    return v[TRIALS / 2];
}

static const char *SU_PATHS[] = {
    "/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su", "/system/su", "/data/local/su",
    "/data/local/bin/su", "/data/local/xbin/su", "/system/sbin/su", "/vendor/bin/su", "/product/bin/su",
    "/debug_ramdisk/su", "/data/adb/magisk", "/data/adb/ksu", "/data/adb/ap",
};
#define N_SU (sizeof SU_PATHS / sizeof *SU_PATHS)

/* Functions whose entry is checked against libc on disk, in catalogue order F146-F154. */
static const char *PROLOGUE_FUNCS[] = {"open", "read", "stat", "access", "fopen", "ptrace", "dlopen", "mmap", "syscall"};
#define N_PRO (sizeof PROLOGUE_FUNCS / sizeof *PROLOGUE_FUNCS)

EXPORT JNIEXPORT void JNICALL
Java_com_example_demo_features_probes_NativeProbes_nop(JNIEnv *env, jclass cls) {
    (void) env;
    (void) cls;
}

EXPORT JNIEXPORT jstring JNICALL
Java_com_example_demo_features_probes_NativeProbes_report(JNIEnv *env, jclass cls) {
    (void) cls;
    sb_t s = {malloc(4096), 0, 4096};
    if (!s.buf) return NULL;
    sb_add(&s, "{");

    /* F039 / F040: su paths via raw syscall vs libc */
    int disagree = 0, svc_hits = 0;
    sb_add(&s, "\"su_svc\":[");
    for (size_t i = 0; i < N_SU; i++) {
        int raw = raw_exists(SU_PATHS[i]);
        int lib = access(SU_PATHS[i], F_OK) == 0;
        if (raw != lib) disagree++;
        if (raw) { if (svc_hits++) sb_add(&s, ","); sb_str(&s, SU_PATHS[i]); }
    }
    sb_add(&s, "],\"su_disagree\":%d,", disagree);

    /* F146-F155: first 16 bytes of libc / libdl entry points vs the file they were mapped from */
    void *libc = dlopen("libc.so", RTLD_NOW | RTLD_NOLOAD);
    sb_add(&s, "\"prologue\":{");
    for (size_t i = 0; i < N_PRO; i++) {
        void *fn = libc ? dlsym(libc, PROLOGUE_FUNCS[i]) : NULL;
        if (!fn) fn = dlsym(RTLD_DEFAULT, PROLOGUE_FUNCS[i]);
        long d = fn ? diff_with_file((uintptr_t) fn, 16) : -1;
        sb_add(&s, "%s\"%s\":%ld", i ? "," : "", PROLOGUE_FUNCS[i], d);
    }
    sb_add(&s, "},");

    /* F156 / F157: this library's GOT entries vs libc's own symbols */
    struct { const char *name; void *got; } got[] = {
        {"open", (void *) &open}, {"read", (void *) &read}, {"close", (void *) &close},
        {"access", (void *) &access}, {"stat", (void *) &stat}, {"mmap", (void *) &mmap},
        {"ptrace", (void *) &ptrace}, {"fopen", (void *) &fopen},
    };
    int got_mismatch = 0, got_outside = 0;
    for (size_t i = 0; i < sizeof got / sizeof *got; i++) {
        void *real = libc ? dlsym(libc, got[i].name) : NULL;
        if (real && real != got[i].got) got_mismatch++;
        Dl_info info;
        if (!dladdr(got[i].got, &info) || !info.dli_fname || !strstr(info.dli_fname, "libc.so")) got_outside++;
    }
    sb_add(&s, "\"got_checked\":%zu,\"got_mismatch\":%d,\"got_outside\":%d,",
           sizeof got / sizeof *got, got_mismatch, got_outside);

    /* F159: libc vs raw syscall results for calls that must agree */
    int svc_diff = 0;
    if ((long) getpid() != raw_syscall4(__NR_getpid, 0, 0, 0, 0)) svc_diff++;
    if ((long) getuid() != raw_syscall4(__NR_getuid, 0, 0, 0, 0)) svc_diff++;
    if ((access("/proc/self/exe", F_OK) == 0) != raw_exists("/proc/self/exe")) svc_diff++;
    if ((access("/system/bin/sh", F_OK) == 0) != raw_exists("/system/bin/sh")) svc_diff++;
    sb_add(&s, "\"svc_libc_diff\":%d,", svc_diff + disagree);

    /* F163: JNIEnv function table entries outside libart */
    void **table = (void **) (*env);
    size_t n_fn = sizeof(struct JNINativeInterface) / sizeof(void *);
    int jni_outside = 0, jni_checked = 0;
    for (size_t i = 4; i < n_fn; i++) {  /* first four are reserved NULLs */
        if (!table[i]) continue;
        jni_checked++;
        Dl_info info;
        if (!dladdr(table[i], &info) || !info.dli_fname || !strstr(info.dli_fname, "libart")) jni_outside++;
    }
    sb_add(&s, "\"jni_checked\":%d,\"jni_outside\":%d,", jni_checked, jni_outside);

    /* F210 / F213 / F219 / F220: latencies (median of 64) */
    uint64_t t[TRIALS];
    for (int i = 0; i < TRIALS; i++) { uint64_t a = now_ns(); (void) getpid(); t[i] = now_ns() - a; }
    uint64_t getpid_libc = median(t);
    for (int i = 0; i < TRIALS; i++) { uint64_t a = now_ns(); raw_syscall4(__NR_getpid, 0, 0, 0, 0); t[i] = now_ns() - a; }
    uint64_t getpid_svc = median(t);
    for (int i = 0; i < TRIALS; i++) {
        uint64_t a = now_ns();
        void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p != MAP_FAILED) munmap(p, 4096);
        t[i] = now_ns() - a;
    }
    uint64_t mmap_ns = median(t);
    for (int i = 0; i < TRIALS; i++) {
        uint64_t a = now_ns();
        (void) dlsym(libc ? libc : RTLD_DEFAULT, "open");
        t[i] = now_ns() - a;
    }
    uint64_t dlsym_ns = median(t);
    sb_add(&s, "\"getpid_libc_ns\":%llu,\"getpid_svc_ns\":%llu,\"mmap_ns\":%llu,\"dlsym_ns\":%llu,",
           (unsigned long long) getpid_libc, (unsigned long long) getpid_svc,
           (unsigned long long) mmap_ns, (unsigned long long) dlsym_ns);

    /* F360 / F368: this library's own code vs its file, and where it was loaded from */
    mapping_t self;
    uintptr_t me = (uintptr_t) &Java_com_example_demo_features_probes_NativeProbes_report;
    if (find_mapping(me, &self)) {
        long d = diff_with_file(self.start, self.end - self.start);
        sb_add(&s, "\"own_text_bytes\":%lu,\"own_text_diff\":%ld,\"own_path\":",
               (unsigned long) (self.end - self.start), d);
        sb_str(&s, self.path);
    } else {
        sb_add(&s, "\"own_text_diff\":-1,\"own_path\":\"\"");
    }

    if (libc) dlclose(libc);
    sb_add(&s, "}");
    jstring out = (*env)->NewStringUTF(env, s.buf);
    free(s.buf);
    return out;
}
