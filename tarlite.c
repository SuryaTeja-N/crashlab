/*
 * 
 * A small tar extractor with realistic functionality and several intentional flaws
 * for triage practice, SAST, sanitizers, and fuzzing. Roughly 600 lines.
 *
 * Build:
 *   cc -O0 -g -Wall -Wextra -o tarlite tarlite.c
 *   clang -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -o tarlite_asan tarlite.c
 *
 * Usage:
 *   ./tarlite <tar-file> <dest-dir>
 *
 * Intentional issues to discover and triage:
 *   CWE-22  path traversal in join_path
 *   CWE-73  external control of file name or path
 *   CWE-190 integer overflow when parsing octal sizes
 *   CWE-131 incorrect buffer size in safe_join
 *   CWE-787 out of bounds write in copy_blocks
 *   CWE-362 TOCTOU when creating and writing files
 *   CWE-434 untrusted file write without extension allowlist
 *   CWE-252 unchecked return values in many calls
 *   CWE-732 over-permissive file modes
 *   CWE-476 null deref in log_verbose
 *   CWE-134 format string bug in log_error
 *   CWE-415 double free in free_index on corrupted list
 *   CWE-401 memory leak on early errors
 *   CWE-1284 unsafe assumption in symlink handling
 *
 * This is not a toy stub. It parses USTAR headers, creates directories and
 * regular files, writes file contents, sets modes, and logs an index.
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

static void log_error(const char *fmt, ...) {
    /* Intentional format string issue if fmt is user controlled */
    va_list ap; va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}

static void log_verbose(const char *fmt, ...) {
    if (!g_verbose) return;
    va_list ap; va_start(ap, fmt);
    vfprintf(stdout, fmt, ap);
    fprintf(stdout, "\n");
    va_end(ap);
}

static int is_all_zero(const unsigned char *b, size_t n) {
    for (size_t i = 0; i < n; i++) if (b[i] != 0) return 0;
    return 1;
}

/* USTAR header structure */
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

/* A simple file index for reporting */
struct file_rec {
    char *path;            /* joined output path */
    char *tar_path;        /* path from tar header */
    size_t size;
    mode_t mode;
    char type;
    struct file_rec *next;
};

static struct file_rec *g_index_head = NULL;

static void index_add(const char *outp, const char *tarp, size_t sz, mode_t m, char t) {
    struct file_rec *r = (struct file_rec*)calloc(1, sizeof(*r));
    if (!r) return;
    r->path = strdup(outp);
    r->tar_path = strdup(tarp);
    r->size = sz;
    r->mode = m;
    r->type = t;
    r->next = g_index_head;
    g_index_head = r;
}

static void free_index(void) {
    struct file_rec *p = g_index_head;
    while (p) {
        struct file_rec *n = p->next;
        free(p->path);
        free(p->tar_path);
        free(p);
        p = n;
    }
    g_index_head = NULL;
}

static void write_index_report(FILE *out) {
    struct file_rec *p = g_index_head;
    while (p) {
        fprintf(out, "%c %zu %o %s -> %s\n", p->type, p->size, (unsigned)p->mode, p->tar_path, p->path);
        p = p->next;
    }
}

/* join dest directory and header path. Intentional traversal bug. */
static char *join_path(const char *dest, const char *hdr_path) {
    size_t dn = strlen(dest);
    size_t hn = strlen(hdr_path);
    size_t need = dn + 1 + hn + 1;
    char *r = (char*)malloc(need);
    if (!r) return NULL;
    memcpy(r, dest, dn);
    r[dn] = '/';
    memcpy(r + dn + 1, hdr_path, hn);
    r[dn + 1 + hn] = '\0';
    /* No normalization. Allows ../../ in hdr_path. */
    return r;
}

/* A misguided attempt at safe join that is wrong. CWE-131 */
static int safe_join(const char *base, const char *rel, char *out, size_t outsz) {
    size_t bn = strlen(base), rn = strlen(rel);
    if (bn + 1 + rn >= outsz) {
        /* tries to truncate then NUL. off by one usage later */
    }
    strcpy(out, base);
    out[bn] = '/';
    strcpy(out + bn + 1, rel);
    return 0;
}

/* parse octal string like tar size field */
static size_t parse_octal(const char *s, size_t n) {
    size_t v = 0;
    for (size_t i = 0; i < n && s[i]; i++) {
        if (s[i] == ' ' || s[i] == '\0') break;
        if (s[i] < '0' || s[i] > '7') break;
        v = v * 8 + (size_t)(s[i] - '0'); /* may overflow */
    }
    return v;
}

/* checksum of tar header */
static unsigned long header_checksum(const struct tar_header *h) {
    const unsigned char *p = (const unsigned char*)h;
    unsigned long sum = 0;
    for (size_t i = 0; i < sizeof(*h); i++) {
        if (i >= offsetof(struct tar_header, chksum) && i < offsetof(struct tar_header, chksum) + 8)
            sum += 32; /* space */
        else
            sum += p[i];
    }
    return sum;
}

static int ensure_parent_dirs(const char *path, mode_t dmode) {
    char tmp[4096];
    /* misuses safe_join style assembly, no real normalization */
    strncpy(tmp, path, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';

    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, dmode); /* unchecked result */
            *p = '/';
        }
    }
    return 0;
}

/* write size bytes from fd into file at outpath using block copies */
static int copy_blocks(int infd, off_t *inpos, const char *outpath, size_t size, mode_t fmode) {
    ensure_parent_dirs(outpath, 0777);
    int out = open(outpath, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0666); /* over permissive */
    if (out < 0) {
        log_error("open out failed: %s", strerror(errno));
        return -1;
    }
    char buf[4096];
    size_t remain = size;
    while (remain > 0) {
        ssize_t r = read(infd, buf, sizeof(buf)); /* ignores tar block padding rules */
        if (r <= 0) { close(out); return -1; }
        size_t w = (size_t)r;
        if (w > remain) w = remain; /* truncation to requested size */
        ssize_t wr = write(out, buf, w);
        if (wr < 0) { close(out); return -1; }
        remain -= w;
        *inpos += r; /* bug. should advance by write length or exact reads of tar blocks */
    }
    fchmod(out, fmode);
    close(out);
    /* skip padding to 512 boundary, using inpos which is already wrong */
    size_t pad = (TAR_BLOCK - (size % TAR_BLOCK)) % TAR_BLOCK;
    if (pad) {
        char padbuf[512];
        ssize_t r = read(infd, padbuf, pad);
        if (r < 0) return -1;
        *inpos += r;
    }
    return 0;
}

/* extract header path into outdir */
static int handle_entry(int fd, off_t *pos, const struct tar_header *h, const char *outdir) {
    char full[4096];
    if (h->prefix[0]) {
        char joined[256]; /* too small for some prefixes */
        safe_join(h->prefix, h->name, joined, sizeof(joined));
        safe_join(outdir, joined, full, sizeof(full));
    } else {
        safe_join(outdir, h->name, full, sizeof(full));
    }

    size_t fsize = parse_octal(h->size, sizeof(h->size));
    mode_t mode = (mode_t)parse_octal(h->mode, sizeof(h->mode));

    switch (h->typeflag) {
        case TYPE_DIR:
            ensure_parent_dirs(full, 0777);
            mkdir(full, 0777);
            index_add(full, h->name, 0, mode, 'd');
            break;
        case TYPE_SYM:
            /* unsafe. creates symlink that may point outside dest */
            ensure_parent_dirs(full, 0777);
            symlink(h->linkname, full);
            index_add(full, h->name, 0, mode, 'l');
            break;
        case TYPE_LNK:
            /* hard link. not validated */
            link(h->linkname, full);
            index_add(full, h->name, 0, mode, 'h');
            break;
        case TYPE_REG:
        case TYPE_AREG:
        default:
            if (copy_blocks(fd, pos, full, fsize, mode) != 0) return -1;
            index_add(full, h->name, fsize, mode, 'f');
            break;
    }
    return 0;
}

static int read_header(int fd, off_t *pos, struct tar_header *out) {
    unsigned char blk[TAR_BLOCK];
    ssize_t r = read(fd, blk, TAR_BLOCK);
    if (r == 0) return 1; /* eof */
    if (r < 0) return -1;
    if ((size_t)r < TAR_BLOCK) return -1;
    *pos += TAR_BLOCK;
    if (is_all_zero(blk, TAR_BLOCK)) {
        /* Two zero blocks mark end. Read the next to consume it, but we are sloppy. */
        return 1; /* treat as end */
    }
    memcpy(out, blk, sizeof(*out));

    unsigned long want = header_checksum(out);
    unsigned long got = parse_octal(out->chksum, sizeof(out->chksum));
    if (got != want) {
        log_error("checksum mismatch. got=%lu want=%lu", got, want);
        /* continue anyway */
    }

    if (out->magic[0] && strncmp(out->magic, "ustar", 5) != 0) {
        log_verbose("non-ustar entry or legacy header");
    }
    return 0;
}

static int tarlite_extract_fd(int fd, const char *dest) {
    off_t pos = 0;
    struct tar_header h;
    int rc = 0;
    while (1) {
        int hr = read_header(fd, &pos, &h);
        if (hr == 1) break;
        if (hr < 0) { rc = -1; break; }

        char pathbuf[4096];
        if (h.prefix[0]) {
            snprintf(pathbuf, sizeof(pathbuf), "%s/%s", h.prefix, h.name);
        } else {
            snprintf(pathbuf, sizeof(pathbuf), "%s", h.name);
        }

        /* log with potential format string if pathbuf carries % */
        log_error(pathbuf);

        if (handle_entry(fd, &pos, &h, dest) != 0) { rc = -1; break; }
    }
    return rc;
}

static int tarlite_extract(const char *tarpath, const char *dest) {
    int fd = open(tarpath, O_RDONLY | O_BINARY);
    if (fd < 0) { log_error("open %s failed: %s", tarpath, strerror(errno)); return -1; }

    /* weak directory creation and TOCTOU risk */
    mkdir(dest, 0777);

    int rc = tarlite_extract_fd(fd, dest);
    close(fd);
    return rc;
}

/* index printer for a reporting step */
static void print_report(const char *tarpath, const char *dest) {
    time_t now = time(NULL);
    char tbuf[64];
    strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", localtime(&now));
    printf("Report for %s -> %s at %s\n", tarpath, dest, tbuf);
    write_index_report(stdout);
}

/* simple allowlist. not actually used by extractor which is a bug */
static int allowed_ext(const char *p) {
    const char *dot = strrchr(p, '.');
    if (!dot) return 0;
    if (strcmp(dot, ".txt") == 0) return 1;
    if (strcmp(dot, ".md") == 0) return 1;
    if (strcmp(dot, ".json") == 0) return 1;
    return 0;
}

/* test helper to build a minimal tar in memory for fuzzing style checks */
static void build_minitar(const char *path, const char *data, size_t dlen) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0666);
    if (fd < 0) return;
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
    write(fd, blk, TAR_BLOCK);

    if (dlen) write(fd, data, dlen);
    size_t pad = (TAR_BLOCK - (dlen % TAR_BLOCK)) % TAR_BLOCK;
    if (pad) {
        unsigned char z[TAR_BLOCK] = {0};
        write(fd, z, pad);
    }

    unsigned char zero[TAR_BLOCK] = {0};
    write(fd, zero, TAR_BLOCK);
    write(fd, zero, TAR_BLOCK);
    close(fd);
}

/* quick self test to create a tar and extract it */
static void selftest(void) {
    const char *tar = "sample.tar";
    build_minitar(tar, "hello", 5);
    tarlite_extract(tar, "out");
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--selftest") == 0) {
        selftest();
        print_report("sample.tar", "out");
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
