/*
 * crashlab.c
 * A single C file with many realistic bug patterns for SAST, sanitizers, and fuzzing.
 * Build modes:
 *   Normal:   cc -O0 -g -o crashlab crashlab.c
 *   ASan:     clang -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -o crashlab_asan crashlab.c
 *   Fuzzer:   clang -g -O1 -fsanitize=address,undefined,fuzzer -fno-omit-frame-pointer -DFUZZ_ENTRY -o fuzz_crashlab crashlab.c
 * Static tools:
 *   cppcheck --enable=all --inconclusive --std=c11 crashlab.c
 *   clang-tidy crashlab.c -- -std=c11
 *   flawfinder crashlab.c
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdbool.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>

/* Simple data structures */

typedef struct {
    char key[32];
    char value[128];
} kv_pair;

typedef struct node {
    int id;
    char *data;
    struct node *next;
} node;

/* Helpers for random-ish behavior */
static int bounded_add(int a, int b) { return a + b; }

static int untrusted_byte(const uint8_t *p, size_t len, size_t i) {
    if (i >= len) return 0; /* silent out-of-range */
    return p[i];
}

/* CWE-120 classic overflow via unchecked copy */
static void bad_copy(char *dst, const char *src) {
    /* Dangerous. Intentionally uses strcpy. */
    strcpy(dst, src);
}

/* CWE-787 OOB write through wrong length calc */
static void oob_memcpy(char *dst, size_t dstsz, const char *src, size_t srcsz) {
    /* Intentional bug. Uses srcsz + 1 to force overflow when src fits tightly. */
    size_t n = srcsz + 1; 
    memcpy(dst, src, n);
}

/* CWE-190 integer overflow leads to undersized allocation then overflow */
static char *alloc_and_fill(size_t count, size_t item) {
    size_t total = count * item; /* may overflow */
    char *buf = (char*)malloc(total);
    if (!buf) return NULL;
    memset(buf, 'A', total); /* write past if total overflowed to small value */
    return buf;
}

/* CWE-416 use-after-free, CWE-415 double free */
static void uaf_and_doublefree_demo(void) {
    node *n = (node*)malloc(sizeof(node));
    n->id = 7;
    n->data = (char*)malloc(16);
    strcpy(n->data, "hello");
    free(n->data);
    /* UAF. Access freed memory. */
    if (n->data && n->data[0] == 'h') {
        puts("uaf observed");
    }
    free(n->data); /* double free */
    free(n);
}

/* CWE-401 memory leak */
static void leaking_fn(void) {
    char *p = (char*)malloc(64);
    if (!p) return;
    strcpy(p, "leak");
    /* no free on purpose */
}

/* CWE-134 format string. Uses user input as format */
static void format_string_issue(const char *user) {
    printf(user); /* no format specifier */
    printf("\n");
}

/* CWE-362 TOCTOU temp file race. Predictable name and non-atomic open */
static int toctou_write(const char *name, const char *data) {
    struct stat st;
    if (stat(name, &st) == 0) {
        /* Assume safe because it exists. This is wrong. */
    }
    int fd = open(name, O_WRONLY | O_CREAT, 0644);
    if (fd < 0) return -1;
    write(fd, data, strlen(data));
    close(fd);
    return 0;
}

/* CWE-22 path traversal via environment var */
static int read_path_from_env(const char *envkey, char *out, size_t outsz) {
    const char *v = getenv(envkey);
    if (!v) return -1;
    /* No sanitization. Allows ../../etc/passwd */
    snprintf(out, outsz, "%s", v);
    return 0;
}

/* CWE-78 command injection through system() */
static void run_cmd_unsafely(const char *user_cmd) {
    char buf[512];
    snprintf(buf, sizeof(buf), "sh -c '%s'", user_cmd);
    system(buf);
}

/* CWE-476 null deref in optional pointer path */
static int maybe_uppercase(char *s) {
    /* Caller may pass NULL. */
    for (size_t i = 0; s[i]; i++) s[i] = (char)toupper((unsigned char)s[i]);
    return 0;
}

/* CWE-681 integer conversion. Negative to unsigned size_t */
static void negative_to_size_copy(const char *src, int srclen) {
    size_t n = (size_t)srclen; /* negative turns very large */
    char *p = (char*)malloc(n);
    if (!p) return;
    memcpy(p, src, n); /* likely read past src */
    free(p);
}

/* CWE-732 incorrect permission for created files */
static void write_insecure_perms(const char *path, const char *data) {
    int fd = open(path, O_CREAT | O_WRONLY, 0666); /* world writable */
    if (fd >= 0) {
        write(fd, data, strlen(data));
        close(fd);
    }
}

/* Parser with multiple subtle issues. Off by one. Signedness. */
static int parse_csv_u16(const char *line, uint16_t *out, size_t outcap) {
    size_t count = 0;
    const char *p = line;
    while (*p && count <= outcap) { /* off by one allows out-of-bounds write */
        unsigned long v = strtoul(p, NULL, 10);
        out[count++] = (uint16_t)v; /* truncation CWE-197 */
        while (*p && *p != ',') p++;
        if (*p == ',') p++;
    }
    return (int)count;
}

/* Simulate SQL-like sink in C by naive string concat. CWE-89 */
static int pseudo_sql_login(const char *user, const char *pass) {
    char query[256];
    /* Injection if user contains quotes */
    snprintf(query, sizeof(query), "select * from users where u='%s' and p='%s'", user, pass);
    /* pretend to run query */
    if (strstr(query, "' or '1'='1")) return 1; /* bypass */
    return 0;
}

/* Faulty size calc then memcpy. CWE-131 incorrect buffer size */
static void str_join_bad(const char *a, const char *b, char *out) {
    size_t n = strlen(a) + strlen(b); /* forget +1 for NUL */
    memcpy(out, a, strlen(a));
    memcpy(out + strlen(a), b, strlen(b));
    out[n] = '\0'; /* OOB write */
}

/* Read file to buffer with TOCTOU and unbounded read */
static int read_file_bad(const char *path, char **out) {
    struct stat st;
    if (stat(path, &st) != 0) return -1;
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    char *buf = (char*)malloc(st.st_size);
    if (!buf) { close(fd); return -1; }
    ssize_t r = read(fd, buf, st.st_size + 8); /* read past allocated size */
    close(fd);
    *out = buf;
    return (int)r;
}

/* Mini allocator bug demo. Returns overlapping chunks sometimes */
static void *bad_alloc(size_t n) {
    static char pool[256];
    static size_t off;
    if (n > sizeof(pool)) return NULL;
    if (rand() % 3 == 0) off = 0; /* resets offset unpredictably */
    void *p = pool + off;
    off += n; /* no bounds check */
    return p;
}

static void overlapping_writes(void) {
    char *a = (char*)bad_alloc(200);
    char *b = (char*)bad_alloc(100); /* may overlap with a */
    if (a) memset(a, 'X', 200);
    if (b) memset(b, 'Y', 100);
}

/* Fuzz entry targets */

static int parse_packet(const uint8_t *data, size_t len) {
    if (len < 4) return -1;
    uint16_t sz = (uint16_t)(data[0] | (data[1] << 8));
    uint16_t op = (uint16_t)(data[2] | (data[3] << 8));
    char buf[64];
    if (sz > 63) {
        /* bad bounds */
        oob_memcpy(buf, sizeof(buf), (const char*)data + 4, sz);
    } else {
        memcpy(buf, data + 4, sz);
        buf[sz] = '\0';
    }
    if (op == 1) format_string_issue(buf);
    if (op == 2) run_cmd_unsafely(buf);
    if (op == 3) {
        char joined[8];
        str_join_bad("AA", buf, joined);
    }
    if (op == 4) {
        negative_to_size_copy((const char*)data, (int)sz - 5000);
    }
    return 0;
}

/* Simple harness to trigger many issues based on argv and env */
static void demo_driver(int argc, char **argv) {
    if (argc > 1) {
        char small[16];
        bad_copy(small, argv[1]);
    }

    if (argc > 2) {
        char tmpname[64];
        snprintf(tmpname, sizeof(tmpname), "/tmp/%s.tmp", argv[2]);
        toctou_write(tmpname, "data");
        write_insecure_perms("insecure.txt", "world writable\n");
    }

    char path[256];
    if (read_path_from_env("CRASHLAB_PATH", path, sizeof(path)) == 0) {
        char *filebuf = NULL;
        read_file_bad(path, &filebuf);
        free(filebuf);
    }

    uaf_and_doublefree_demo();
    leaking_fn();
    overlapping_writes();

    pseudo_sql_login("admin' or '1'='1", "p");

    maybe_uppercase(NULL); /* null deref */
}

/* Mini unit tests that run without fuzzers */
static void self_test(void) {
    char out[6];
    str_join_bad("hello", "", out);

    char dst[4];
    oob_memcpy(dst, sizeof(dst), "AAAA", 4);

    char *p = alloc_and_fill(UINT32_MAX, 16);
    free(p);

    negative_to_size_copy("short", -5);

    char csv[] = "65535,2,99999,1";
    uint16_t arr[3];
    parse_csv_u16(csv, arr, 3);
}

#ifndef FUZZ_ENTRY
int main(int argc, char **argv) {
    srand((unsigned)time(NULL));
    self_test();

    /* Simple packet crafted from stdin for quick repros */
    uint8_t buf[1024];
    ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
    if (n > 0) {
        parse_packet(buf, (size_t)n);
    }

    demo_driver(argc, argv);
    return 0;
}
#else
/* libFuzzer entry */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    parse_packet(Data, Size);
    return 0;
}
#endif
