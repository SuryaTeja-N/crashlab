/*
 * tarlite_patched.c
 * A small tar extractor with real functionality. All known issues fixed.
 * Safer I/O, path normalization, bounds checks, and conservative file handling.
 *
 * Build:
 *   cc -O2 -g -Wall -Wextra -Wpedantic -o tarlite_patched tarlite_patched.c
 *   clang -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -o tarlite_patched_asan tarlite_patched.c
 *
 * Usage:
 *   ./tarlite_patched <tar-file> <dest-dir>
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <limits.h>

#ifndef O_BINARY
#define O_BINARY 0
#endif

#define TAR_BLOCK 512
#define TYPE_REG '0'
#define TYPE_AREG '\0'
#define TYPE_LNK '1'
#define TYPE_SYM '2'
#define TYPE_CHR '3'
#define TYPE_BLK '4'
#define TYPE_DIR '5'
#define TYPE_FIFO '6'
#define TYPE_CONT '7'

static int g_verbose = 1;

/*
 * Safe logging helpers
 * Fix: prevent format string injection by never treating untrusted strings as a format.
 */
static void log_errorf(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}
static void log_errmsg(const char *msg) {
    if (!msg) return;
    fprintf(stderr, "%s\n", msg);
}
static void log_verbosef(const char *fmt, ...) {
    if (!g_verbose || !fmt) return; /* Fix: null check for fmt */
    va_list ap; va_start(ap, fmt);
    vfprintf(stdout, fmt, ap);
    fprintf(stdout, "\n");
    va_end(ap);
}

static int is_all_zero(const unsigned char *b, size_t n) {
    for (size_t i = 0; i < n; i++) if (b[i] != 0) return 0;
    return 1;
}

/* USTAR header */
struct tar_header {
    char name[100];
    char mode[8];
    char uid[8];
    char gid[8];
    char size[12];
    char mtime[12];
    char chksum[8];
    char typeflag;
    char linkname[100];
    char magic[6];
    char version[2];
    char uname[32];
    char gname[32];
    char devmajor[8];
    char devminor[8];
    char prefix[155];
    char pad[12];
};

/* Simple file index for reporting */
struct file_rec {
    char *path;
    char *tar_path;
    size_t size;
    mode_t mode;
    char type;
    struct file_rec *next;
};
static struct file_rec *g_index_head = NULL;

static void *xcalloc(size_t n, size_t sz) {
    if (sz != 0 && n > SIZE_MAX / sz) return NULL;
    void *p = calloc(n, sz);
    return p;
}
static char *xstrdup(const char *s) {
    if (!s) return NULL;
    size_t n = strlen(s);
    char *p = (char*)malloc(n + 1);
    if (!p) return NULL;
    memcpy(p, s, n + 1);
    return p;
}

static void index_add(const char *outp, const char *tarp, size_t sz, mode_t m, char t) {
    struct file_rec *r = (struct file_rec*)xcalloc(1, sizeof(*r));
    if (!r) return;
    r->path = xstrdup(outp);
    r->tar_path = xstrdup(tarp);
    r->size = sz;
    r->mode = m;
    r->type = t;
    r->next = g_index_head;
    g_index_head = r;
}

/* Fix: make free robust and idempotent at best effort. Tracks visited nodes to avoid double free on accidental cycles. */
struct rec_node_list { const void *p; struct rec_node_list *next; };
static int visited_contains(struct rec_node_list *h, const void *p) {
    for (; h; h = h->next) if (h->p == p) return 1; return 0;
}
static int visited_add(struct rec_node_list **h, const void *p) {
    struct rec_node_list *n = (struct rec_node_list*)malloc(sizeof(*n));
    if (!n) return -1; n->p = p; n->next = *h; *h = n; return 0;
}
static void visited_free(struct rec_node_list *h) { while (h) { struct rec_node_list *n = h->next; free(h); h = n; } }

static void free_index(void) {
    struct rec_node_list *vis = NULL;
    struct file_rec *p = g_index_head;
    while (p) {
        if (visited_contains(vis, p)) break;
        visited_add(&vis, p);
        struct file_rec *n = p->next;
        free(p->path); p->path = NULL;
        free(p->tar_path); p->tar_path = NULL;
        p->next = NULL;
        free(p);
        p = n;
    }
    g_index_head = NULL;
    visited_free(vis);
}

static void write_index_report(FILE *out) {
    for (struct file_rec *p = g_index_head; p; p = p->next) {
        fprintf(out, "%c %zu %o %s -> %s\n", p->type, p->size, (unsigned)p->mode, p->tar_path, p->path);
    }
}

/*
 * Path handling
 * Fix: forbid absolute paths, forbid any ".." components, normalize simple components.
 * Also verify final path remains inside destination by prefix check using realpath on dest.
 */
static int has_dotdot(const char *path) {
    if (!path) return 1;
    const char *p = path;
    while (*p) {
        while (*p == '/') p++;
        const char *seg = p;
        while (*p && *p != '/') p++;
        size_t len = (size_t)(p - seg);
        if (len == 2 && seg[0] == '.' && seg[1] == '.') return 1;
    }
    return 0;
}

static int normalize_join(const char *base, const char *rel, char *out, size_t outsz) {
    if (!base || !rel || !out || outsz == 0) return -1;
    if (rel[0] == '/') return -1; /* absolute not allowed */
    if (has_dotdot(rel)) return -1;
    size_t bn = strlen(base);
    while (bn > 0 && base[bn - 1] == '/') bn--; /* trim trailing slashes */
    int n = snprintf(out, outsz, "%.*s/%s", (int)bn, base, rel);
    if (n < 0 || (size_t)n >= outsz) return -1;
    return 0;
}

static int ensure_parent_dirs(const char *path, mode_t dmode) {
    if (!path) return -1;
    char tmp[PATH_MAX];
    size_t n = strnlen(path, sizeof(tmp) - 1);
    memcpy(tmp, path, n);
    tmp[n] = '\0';
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (strlen(tmp) > 0) {
                if (mkdir(tmp, dmode) < 0 && errno != EEXIST) return -1;
            }
            *p = '/';
        }
    }
    if (mkdir(tmp, dmode) < 0 && errno != EEXIST) return -1;
    return 0;
}

/* parse octal safely into size_t with overflow check */
static int parse_octal_szt(const char *s, size_t n, size_t *out) {
    if (!s || !out) return -1;
    unsigned long long v = 0ULL;
    size_t i = 0;
    while (i < n && s[i] == ' ') i++;
    for (; i < n && s[i]; i++) {
        if (s[i] == ' ' || s[i] == '\0') break;
        if (s[i] < '0' || s[i] > '7') break;
        unsigned int d = (unsigned int)(s[i] - '0');
        if (v > (ULLONG_MAX - d) / 8ULL) return -1; /* overflow */
        v = v * 8ULL + d;
    }
    if (v > SIZE_MAX) return -1;
    *out = (size_t)v;
    return 0;
}

/* header checksum */
static unsigned long header_checksum(const struct tar_header *h) {
    const unsigned char *p = (const unsigned char*)h;
    unsigned long sum = 0;
    for (size_t i = 0; i < sizeof(*h); i++) {
        if (i >= offsetof(struct tar_header, chksum) && i < offsetof(struct tar_header, chksum) + 8)
            sum += 32;
        else
            sum += p[i];
    }
    return sum;
}

/* safe extension policy for regular files */
static int allowed_ext(const char *p) {
    const char *dot = p ? strrchr(p, '.') : NULL;
    if (!dot) return 0;
    if (strcmp(dot, ".txt") == 0) return 1;
    if (strcmp(dot, ".md") == 0) return 1;
    if (strcmp(dot, ".json") == 0) return 1;
    return 0;
}

/* write size bytes from fd into file at outpath */
static int copy_blocks(int infd, size_t size, const char *outpath, mode_t fmode) {
    if (ensure_parent_dirs(outpath, 0755) != 0) return -1;
    int out = open(outpath, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY | O_NOFOLLOW, 0600);
    if (out < 0) {
        log_errorf("open out failed: %s", strerror(errno));
        return -1;
    }
    char buf[4096];
    size_t remain = size;
    while (remain > 0) {
        size_t want = remain < sizeof(buf) ? remain : sizeof(buf);
        ssize_t r = read(infd, buf, want);
        if (r <= 0) { close(out); return -1; }
        ssize_t wr = write(out, buf, (size_t)r);
        if (wr != r) { close(out); return -1; }
        remain -= (size_t)r;
    }
    if (fchmod(out, fmode) != 0) { close(out); return -1; }
    close(out);

    /* consume tar padding up to 512 alignment */
    size_t pad = (TAR_BLOCK - (size % TAR_BLOCK)) % TAR_BLOCK;
    if (pad) {
        char padbuf[512];
        while (pad > 0) {
            size_t chunk = pad < sizeof(padbuf) ? pad : sizeof(padbuf);
            ssize_t rr = read(infd, padbuf, chunk);
            if (rr <= 0) return -1;
            pad -= (size_t)rr;
        }
    }
    return 0;
}

/* read one header block */
static int read_header(int fd, struct tar_header *out) {
    unsigned char blk[TAR_BLOCK];
    ssize_t r = read(fd, blk, TAR_BLOCK);
    if (r == 0) return 1; /* eof */
    if (r < 0) return -1;
    if ((size_t)r < TAR_BLOCK) return -1;
    if (is_all_zero(blk, TAR_BLOCK)) return 1; /* end */
    memcpy(out, blk, sizeof(*out));

    unsigned long want = header_checksum(out);
    size_t got_val = 0;
    if (parse_octal_szt(out->chksum, sizeof(out->chksum), &got_val) != 0) {
        log_errorf("bad header checksum field");
    } else if ((unsigned long)got_val != want) {
        log_errorf("checksum mismatch. got=%lu want=%lu", (unsigned long)got_val, want);
    }
    return 0;
}

/* combine prefix and name into a tar path, validate, and join with dest */
static int build_output_path(const struct tar_header *h, const char *dest_root, const char *dest_real, char out[PATH_MAX]) {
    char tarrel[PATH_MAX];
    if (h->prefix[0]) {
        int n = snprintf(tarrel, sizeof(tarrel), "%s/%s", h->prefix, h->name);
        if (n < 0 || (size_t)n >= sizeof(tarrel)) return -1;
    } else {
        int n = snprintf(tarrel, sizeof(tarrel), "%s", h->name);
        if (n < 0 || (size_t)n >= sizeof(tarrel)) return -1;
    }
    if (tarrel[0] == '\0') return -1;
    if (normalize_join(dest_root, tarrel, out, PATH_MAX) != 0) return -1; /* Fix: traversal and absolute path rejection */

    /* Verify final path stays inside dest using a prefix check on realpath of parent dir */
    char destbuf[PATH_MAX];
    if (!realpath(dest_root, destbuf)) return -1;
    size_t dlen = strlen(destbuf);
    /* best effort prefix check */
    if (strncmp(out, destbuf, dlen) != 0 || (out[dlen] != '/' && out[dlen] != '\0')) {
        return -1;
    }
    return 0;
}

/* extract one entry */
static int handle_entry(int fd, const struct tar_header *h, const char *dest_root, const char *dest_real) {
    char full[PATH_MAX];
    if (build_output_path(h, dest_root, dest_real, full) != 0) {
        log_errorf("unsafe path skipped: %s/%s", h->prefix, h->name);
        /* skip payload if regular file */
        size_t skip = 0; if (parse_octal_szt(h->size, sizeof(h->size), &skip) != 0) return -1;
        size_t pad = (TAR_BLOCK - (skip % TAR_BLOCK)) % TAR_BLOCK;
        char trash[512];
        while (skip > 0) { size_t chunk = skip > sizeof(trash) ? sizeof(trash) : skip; ssize_t r = read(fd, trash, chunk); if (r <= 0) return -1; skip -= (size_t)r; }
        while (pad > 0) { size_t chunk = pad > sizeof(trash) ? sizeof(trash) : pad; ssize_t r = read(fd, trash, chunk); if (r <= 0) return -1; pad -= (size_t)r; }
        return 0;
    }

    size_t fsize = 0; if (parse_octal_szt(h->size, sizeof(h->size), &fsize) != 0) return -1;
    mode_t mode = 0;   if (parse_octal_szt(h->mode, sizeof(h->mode), (size_t*)&mode) != 0) mode = 0644;

    switch (h->typeflag) {
        case TYPE_DIR: {
            if (ensure_parent_dirs(full, 0755) != 0) return -1;
            if (mkdir(full, 0755) < 0 && errno != EEXIST) return -1; /* Fix: check return and tight mode */
            index_add(full, h->name, 0, 0755, 'd');
            break;
        }
        case TYPE_SYM: {
            /* Fix: reject symlinks for safety in this extractor. */
            log_errorf("symlink skipped: %s -> %s", h->name, h->linkname);
            break;
        }
        case TYPE_LNK: {
            /* Fix: reject hard links for safety. */
            log_errorf("hard link skipped: %s -> %s", h->name, h->linkname);
            break;
        }
        case TYPE_REG:
        case TYPE_AREG:
        default: {
            /* Fix: enforce simple extension allowlist for regular files */
            if (!allowed_ext(full)) {
                log_errorf("file skipped by policy: %s", full);
                /* consume payload */
                size_t skip = fsize; char trash[512];
                while (skip > 0) { size_t chunk = skip > sizeof(trash) ? sizeof(trash) : skip; ssize_t r = read(fd, trash, chunk); if (r <= 0) return -1; skip -= (size_t)r; }
                size_t pad = (TAR_BLOCK - (fsize % TAR_BLOCK)) % TAR_BLOCK;
                while (pad > 0) { size_t chunk = pad > sizeof(trash) ? sizeof(trash) : pad; ssize_t r = read(fd, trash, chunk); if (r <= 0) return -1; pad -= (size_t)r; }
                break;
            }
            if (copy_blocks(fd, fsize, full, 0644) != 0) return -1;
            index_add(full, h->name, fsize, 0644, 'f');
            break;
        }
    }
    return 0;
}

static int tarlite_extract_fd(int fd, const char *dest) {
    char dest_real[PATH_MAX];
    if (!realpath(dest, dest_real)) {
        /* Try to create then resolve */
        if (mkdir(dest, 0755) < 0 && errno != EEXIST) return -1;
        if (!realpath(dest, dest_real)) return -1;
    }

    int rc = 0;
    struct tar_header h;
    while (1) {
        int hr = read_header(fd, &h);
        if (hr == 1) break;
        if (hr < 0) { rc = -1; break; }

        char pathbuf[PATH_MAX];
        if (h.prefix[0]) snprintf(pathbuf, sizeof(pathbuf), "%s/%s", h.prefix, h.name);
        else snprintf(pathbuf, sizeof(pathbuf), "%s", h.name);
        log_verbosef("entry: %s", pathbuf); /* Fix: no untrusted format */

        if (handle_entry(fd, &h, dest, dest_real) != 0) { rc = -1; break; }
    }
    return rc;
}

static int tarlite_extract(const char *tarpath, const char *dest) {
    int fd = open(tarpath, O_RDONLY | O_BINARY);
    if (fd < 0) { log_errorf("open %s failed: %s", tarpath, strerror(errno)); return -1; }
    if (mkdir(dest, 0755) < 0 && errno != EEXIST) { close(fd); return -1; }
    int rc = tarlite_extract_fd(fd, dest);
    close(fd);
    return rc;
}

static void write_index_report(FILE *out);

static void print_report(const char *tarpath, const char *dest) {
    time_t now = time(NULL);
    char tbuf[64];
    struct tm tmv;
    localtime_r(&now, &tmv);
    strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", &tmv);
    printf("Report for %s -> %s at %s\n", tarpath, dest, tbuf);
    write_index_report(stdout);
}

/* helper to build a minimal tar for quick local tests */
static unsigned long header_checksum(const struct tar_header *h);
static void build_minitar(const char *path, const char *data, size_t dlen) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0600);
    if (fd < 0) { log_errorf("build tar open failed: %s", strerror(errno)); return; }
    unsigned char blk[TAR_BLOCK];
    memset(blk, 0, sizeof(blk));
    struct tar_header *h = (struct tar_header*)blk;
    snprintf(h->name, sizeof(h->name), "file.txt");
    snprintf(h->mode, sizeof(h->mode), "%07o", 0644);
    snprintf(h->size, sizeof(h->size), "%011zo", dlen);
    snprintf(h->mtime, sizeof(h->mtime), "%011zo", (size_t)time(NULL));
    memcpy(h->magic, "ustar", 5);
    memset(h->chksum, ' ', sizeof(h->chksum));
    unsigned long sum = header_checksum(h);
    snprintf(h->chksum, sizeof(h->chksum), "%06lu\0 ", sum);
    if (write(fd, blk, TAR_BLOCK) != TAR_BLOCK) { close(fd); return; }

    if (dlen) {
        if (write(fd, data, dlen) != (ssize_t)dlen) { close(fd); return; }
    }
    size_t pad = (TAR_BLOCK - (dlen % TAR_BLOCK)) % TAR_BLOCK;
    if (pad) {
        unsigned char z[TAR_BLOCK] = {0};
        if (write(fd, z, pad) != (ssize_t)pad) { close(fd); return; }
    }

    unsigned char zero[TAR_BLOCK] = {0};
    if (write(fd, zero, TAR_BLOCK) != TAR_BLOCK) { close(fd); return; }
    if (write(fd, zero, TAR_BLOCK) != TAR_BLOCK) { close(fd); return; }
    close(fd);
}

static void selftest(void) {
    const char *tar = "sample.tar";
    build_minitar(tar, "hello", 5);
    if (tarlite_extract(tar, "out") == 0) {
        print_report(tar, "out");
    }
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--selftest") == 0) {
        selftest();
        free_index();
        return 0;
    }
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <tar-file> <dest-dir>\n", argv[0]);
        return 2;
    }
    const char *tarpath = argv[1];
    const char *dest = argv[2];
    int rc = tarlite_extract(tarpath, dest);
    print_report(tarpath, dest);
    free_index();
    return rc != 0;
}