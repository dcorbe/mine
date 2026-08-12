/*
 * statprobe -- drive genuine Pervasive Btrieve 6.15's B_STAT (op 15) against
 * real files, byte for byte, to answer the questions a v5-write STAT reply
 * needs that btrvprobe.c's own `cmd_stat` (built for `sweep.sh`'s summary
 * output) does not:
 *
 *   - the RAW bytes of the reply, not just the fields `cmd_stat` already
 *     parses -- so a Rust serialiser can be checked byte-for-byte, not just
 *     field-for-field;
 *   - what happens when the caller's buffer is shorter than the full reply
 *     (`re/wg33src/SRC/api/gcommlib/DFAAPI.C`'s own callers treat status 22
 *     as "truncated, not failed" -- `dfaPosError`, cited in
 *     docs/plans/2026-08-12-btrieve-finish.md's Task 7 section -- but that is
 *     read off a *record* GET, never confirmed for STAT specifically);
 *   - what the `keyno` argument (`dfaStatus`'s explicit key number, `DFAAPI.C:820`)
 *     actually changes about the reply, if anything.
 *
 * `FileSpec`/`KeySpec` below are copied verbatim from `btrvprobe.c` -- see
 * that file's own comments for what was already measured (WCCSPELS.VIR:
 * reclen 253, pagesize 512, indexes_raw 0x4001, meaning `indexes` is masked
 * to the low byte). This program does not re-derive that shape; it exists to
 * confirm it against MORE files, in RAW bytes, and to answer the buffer- and
 * keyno-shaped questions `cmd_stat` was never asked.
 *
 * BUILD
 *   i686-w64-mingw32-gcc -O2 -Wall -Wextra -o statprobe.exe statprobe.c
 * (not wired into build.sh -- a measurement tool, not a fixture generator
 * anything else depends on; build it by hand when using it, same convention
 * as crtprobe.c/updprobe.c/delprobe.c.)
 *
 * USAGE
 *   statprobe dump  <path> [keyno] [bufsize]
 *     One B_STAT call. keyno defaults to -1 (dfaStat's own convention,
 *     DFAAPI.C:815); bufsize defaults to a buffer larger than any real reply
 *     this file could produce (65535 - PADDING, capped under the 64K ABI
 *     limit btrvprobe.c's own header comment measured). Prints status, the
 *     in/out data length, and every returned byte as hex.
 *   statprobe trunc <path>
 *     Sweeps bufsize from 0 up through the full reply length (and a bit past
 *     it), one B_STAT call per size, reporting status and returned length for
 *     each -- the truncation-boundary measurement.
 *   statprobe keyno <path>
 *     Calls B_STAT once per key 0..indexes-1 plus once at -1, and reports
 *     whether the raw reply differs between them.
 */
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define B_OPEN       0
#define B_CLOSE      1
#define B_STAT      15

#define MODE_READ_ONLY (-2)

#define POSBLK_SIZE  128
/* Must stay < 65536: the engine only reads the low 16 bits of the in/out
 * data-length pointer -- btrvprobe.c's own ABI NOTE, measured there as a
 * status-22 storm when DATA_SIZE was exactly 65536. */
#define DATA_SIZE    32768
#define KEY_SIZE       256

typedef int (__stdcall *BTRCALL_FN)(WORD op, void *posblk, void *databuf,
                                    DWORD *datalen, void *keybuf,
                                    BYTE keylen, char keynum);
static BTRCALL_FN btrcall;

/* Identical layout to btrvprobe.c's FileSpec/KeySpec -- see that file's own
 * comments for what is already measured. Redeclared here (not shared via a
 * header) because these probes are each a single throwaway translation unit,
 * the same convention crtprobe.c's own comment on this explains. */
#pragma pack(push, 1)
typedef struct {
    WORD  reclen;
    WORD  pagesize;
    WORD  indexes_raw;
    DWORD records;
    WORD  flags;
    BYTE  dup_pointers;
    BYTE  unused;
    WORD  allocations;
} FileSpec;

typedef struct {
    WORD  position;
    WORD  length;
    WORD  flags;
    DWORD approx_count;
    BYTE  ext_type;
    BYTE  null_value;
    BYTE  reserved[2];
    BYTE  number;
    BYTE  acs_number;
} KeySpec;
#pragma pack(pop)

static const char *status_name(int st)
{
    switch (st) {
    case 0:  return "OK";
    case 2:  return "I/O error";
    case 3:  return "file not open";
    case 6:  return "invalid key number";
    case 9:  return "end of file";
    case 11: return "invalid filename";
    case 12: return "file not found";
    case 22: return "data buffer too short";
    case 30: return "not a Btrieve file";
    case 46: return "access denied";
    default: return "?";
    }
}

static void die(const char *what, int st)
{
    fprintf(stderr, "FAIL %s: status %d (%s)\n", what, st, status_name(st));
    exit(1);
}

static int open_file(char *posblk, const char *path, int mode)
{
    DWORD dlen = 0;
    char keybuf[KEY_SIZE];

    memset(posblk, 0, POSBLK_SIZE);
    memset(keybuf, 0, sizeof keybuf);
    strncpy(keybuf, path, sizeof keybuf - 1);

    return btrcall(B_OPEN, posblk, NULL, &dlen, keybuf,
                   (BYTE)(strlen(keybuf) + 1), (char)mode);
}

/* One B_STAT call with a caller-chosen buffer size and key number. `data`
 * must be at least `bufsize` bytes. Returns the engine's status; `*outlen`
 * receives whatever the in/out length pointer holds afterward. */
static int do_stat(char *posblk, unsigned char *data, unsigned bufsize,
                   int keyno, DWORD *outlen)
{
    char keybuf[KEY_SIZE];
    DWORD dlen = bufsize;
    int st;

    memset(keybuf, 0, sizeof keybuf);
    memset(data, 0xcc, bufsize); /* 0xcc, not zero: a short write that leaves
                                   * some of the buffer untouched must show up
                                   * as 0xcc bytes in the dump, not be
                                   * indistinguishable from a zeroed field the
                                   * engine wrote on purpose. */
    st = btrcall(B_STAT, posblk, data, &dlen, keybuf, sizeof keybuf - 1,
                (char)keyno);
    *outlen = dlen;
    return st;
}

static void hex_dump(const unsigned char *data, unsigned len)
{
    unsigned i;
    for (i = 0; i < len; i++) {
        if (i % 16 == 0)
            printf("%04x: ", i);
        printf("%02x ", data[i]);
        if (i % 16 == 15 || i + 1 == len)
            printf("\n");
    }
}

static void cmd_dump(const char *path, int keyno, unsigned bufsize)
{
    char posblk[POSBLK_SIZE];
    static unsigned char data[DATA_SIZE];
    DWORD outlen;
    int st;

    if (bufsize > DATA_SIZE)
        bufsize = DATA_SIZE;

    st = open_file(posblk, path, MODE_READ_ONLY);
    if (st != 0)
        die("open", st);

    st = do_stat(posblk, data, bufsize, keyno, &outlen);
    printf("file      %s\n", path);
    printf("keyno     %d\n", keyno);
    printf("bufsize   %u\n", bufsize);
    printf("status    %d (%s)\n", st, status_name(st));
    printf("outlen    %lu\n", (unsigned long)outlen);
    printf("bytes:\n");
    hex_dump(data, outlen <= bufsize ? (unsigned)outlen : bufsize);

    if (st == 0 && outlen >= sizeof(FileSpec)) {
        FileSpec fs;
        memcpy(&fs, data, sizeof fs);
        printf("parsed file spec:\n");
        printf("  reclen      %u\n", fs.reclen);
        printf("  pagesize    %u\n", fs.pagesize);
        printf("  indexes_raw 0x%04x (indexes %u)\n", fs.indexes_raw, fs.indexes_raw & 0xff);
        printf("  records     %lu\n", (unsigned long)fs.records);
        printf("  flags       0x%04x\n", fs.flags);
        printf("  dup_pointers %u\n", fs.dup_pointers);
        printf("  unused      %u\n", fs.unused);
        printf("  allocations %u\n", fs.allocations);

        {
            /* One entry PER SEGMENT, not per key -- WCCBANKS.VIR's one
             * duplicate-permitting key over two segments comes back as TWO
             * KeySpec entries here even though indexes_raw's low byte says
             * 1. Walk every entry that fits in the reply rather than
             * `indexes_raw & 0xff` of them, the same distinction
             * btrvprobe.c's own key_extent() draws. */
            unsigned at;
            unsigned seg = 0;
            for (at = sizeof(FileSpec); at + sizeof(KeySpec) <= outlen; at += sizeof(KeySpec), seg++) {
                KeySpec ks;
                memcpy(&ks, data + at, sizeof ks);
                printf("key spec (segment %u, offset %u):\n", seg, at);
                printf("  position     %u\n", ks.position);
                printf("  length       %u\n", ks.length);
                printf("  flags        0x%04x%s\n", ks.flags,
                      (ks.flags & 0x0010) ? " (ANOSEG: another segment follows)" : "");
                printf("  approx_count %lu\n", (unsigned long)ks.approx_count);
                printf("  ext_type     %u\n", ks.ext_type);
                printf("  null_value   %u\n", ks.null_value);
                printf("  reserved     %02x %02x\n", ks.reserved[0], ks.reserved[1]);
                printf("  number       %u\n", ks.number);
                printf("  acs_number   %u\n", ks.acs_number);
            }
        }
    }

    { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }
}

static void cmd_trunc(const char *path)
{
    char posblk[POSBLK_SIZE];
    static unsigned char data[DATA_SIZE];
    unsigned sizes[] = {
        0, 1, 2, 4, 8, 15, 16, 17, 20, 24, 28, 30, 31, 32, 33, 40, 48, 60, 62,
        63, 64, 65, 78, 79, 80, 81, 96, 100, 200, 300, 400, 500, 600, 640,
        650, 660, 664, 665, 666, 667, 680, 700, 800, 1024,
    };
    unsigned i, n = sizeof sizes / sizeof sizes[0];
    int st;

    st = open_file(posblk, path, MODE_READ_ONLY);
    if (st != 0)
        die("open", st);

    printf("file %s -- truncation sweep\n", path);
    for (i = 0; i < n; i++) {
        DWORD outlen;
        st = do_stat(posblk, data, sizes[i], -1, &outlen);
        printf("bufsize %4u -> status %2d (%-22s) outlen %lu",
              sizes[i], st, status_name(st), (unsigned long)outlen);
        if (sizes[i] > 0) {
            /* Show the last byte actually written, to see whether a short
             * buffer leaves the tail at the 0xcc sentinel (untouched) or the
             * engine wrote something there anyway. */
            unsigned show = sizes[i] < 4 ? sizes[i] : 4;
            unsigned j;
            printf(" tail=");
            for (j = sizes[i] - show; j < sizes[i]; j++)
                printf("%02x", data[j]);
        }
        printf("\n");
    }

    { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }
}

static void cmd_keyno(const char *path)
{
    char posblk[POSBLK_SIZE];
    static unsigned char baseline[DATA_SIZE];
    static unsigned char data[DATA_SIZE];
    DWORD outlen, baselen;
    int st, i, nkeys;

    st = open_file(posblk, path, MODE_READ_ONLY);
    if (st != 0)
        die("open", st);

    st = do_stat(posblk, baseline, DATA_SIZE, -1, &baselen);
    if (st != 0)
        die("stat -1", st);
    nkeys = baseline[4] & 0xff; /* FileSpec.indexes_raw low byte, offset 4 */
    printf("file %s -- keyno sweep (%d keys, keyno=-1 baseline length %lu)\n",
          path, nkeys, (unsigned long)baselen);

    for (i = 0; i < nkeys; i++) {
        int j;
        int differs = 0;
        st = do_stat(posblk, data, DATA_SIZE, i, &outlen);
        if (st != 0) {
            printf("keyno %d -> status %d (%s)\n", i, st, status_name(st));
            continue;
        }
        if (outlen != baselen) {
            differs = 1;
        } else {
            for (j = 0; j < (int)outlen; j++) {
                if (data[j] != baseline[j]) {
                    differs = 1;
                    break;
                }
            }
        }
        printf("keyno %d -> status %d outlen %lu %s\n", i, st,
              (unsigned long)outlen,
              differs ? "DIFFERS from keyno=-1" : "identical to keyno=-1");
        if (differs) {
            /* Show exactly which byte first diverges, so the diff is
             * findable without a second run under a hex-diff tool. */
            unsigned min = outlen < baselen ? outlen : baselen;
            unsigned k;
            for (k = 0; k < min; k++) {
                if (data[k] != baseline[k]) {
                    printf("  first differing byte at offset %u: baseline=%02x keyno=%02x\n",
                          k, baseline[k], data[k]);
                    break;
                }
            }
            if (outlen != baselen)
                printf("  lengths differ: baseline=%lu keyno=%lu\n",
                      (unsigned long)baselen, (unsigned long)outlen);
        }
    }

    { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }
}

int main(int argc, char **argv)
{
    HMODULE dll;

    if (argc < 3) {
        fprintf(stderr,
               "usage: %s dump <path> [keyno] [bufsize]\n"
               "       %s trunc <path>\n"
               "       %s keyno <path>\n",
               argv[0], argv[0], argv[0]);
        return 2;
    }

    dll = LoadLibraryA("WBTRV32.DLL");
    if (!dll) {
        fprintf(stderr, "FAIL: LoadLibrary(WBTRV32.DLL): %lu\n", GetLastError());
        return 1;
    }
    btrcall = (BTRCALL_FN)GetProcAddress(dll, "BTRCALL");
    if (!btrcall) {
        fprintf(stderr, "FAIL: GetProcAddress(BTRCALL): %lu\n", GetLastError());
        return 1;
    }

    if (strcmp(argv[1], "dump") == 0) {
        int keyno = argc > 3 ? atoi(argv[3]) : -1;
        unsigned bufsize = argc > 4 ? (unsigned)strtoul(argv[4], NULL, 0) : 4096;
        cmd_dump(argv[2], keyno, bufsize);
    } else if (strcmp(argv[1], "trunc") == 0) {
        cmd_trunc(argv[2]);
    } else if (strcmp(argv[1], "keyno") == 0) {
        cmd_keyno(argv[2]);
    } else {
        fprintf(stderr, "unknown command %s\n", argv[1]);
        return 2;
    }

    return 0;
}
