/*
 * crtprobe -- drive genuine Pervasive Btrieve 6.15's B_CREATE (op 14) with a
 * caller-specified file/key shape, then insert and read back through it.
 *
 * WHY THIS EXISTS
 *
 * crates/mbbs/src/btrieve/create.rs has to write a Btrieve file's file
 * control record, key descriptors and root pages from scratch. The vendor
 * source (`re/wg33src/SRC/api/gcommlib/DFAAPI.C`'s `dfaCreateSpec`) documents
 * the shape of the *request* B_CREATE takes -- a `FileSpec` followed by one
 * `KeySpec` per key segment, byte-for-byte what `btrvprobe.c`'s `B_STAT`
 * reply already reads (same structs, reused here rather than redeclared) --
 * but says nothing about what bytes the engine actually WRITES in response.
 * `btrvprobe.c`'s own `cmd_create` proved the request shape works, for one
 * hardcoded file. This generalises it: every field of `FileSpec` and every
 * `KeySpec` in the array comes from argv, so one file varying one thing at a
 * time can be created and diffed against the last.
 *
 * **This machine's only working oracle (WBTRV32.DLL/W32MKDE.EXE 6.15) writes
 * v6-format files on CREATE** -- confirmed by hex-dumping
 * `tools/btrieve-oracle/fixtures/DUPKEY30.DAT`, which this same engine built:
 * it opens `4643` ("FC"), the v6 marker `crates/mbbs/src/btrieve.rs`'s
 * `version()` checks for, not the four zero bytes every file MajorMUD ships
 * opens with. `crates/mbbs/src/btrieve.rs`'s own `Block::writable` refuses to
 * write ANY v6 file -- v6 writing is out of scope of the plan that added v6
 * reading. So `create.rs` targets the v5 format instead, measured off
 * `tmp/WCCUSERS.VIR`, `WCCBANKS.VIR`, `WCCACMSR.VIR`, `WCCGANGS.VIR` and
 * `WCCITOWN.VIR` -- five real, virgin (zero-record), v5 files this engine
 * still opens, inserts into and reads back without complaint every day this
 * repo's other oracle-gated tests run. This program's `create` command is
 * still useful for that measurement: it confirms the REQUEST-side ABI
 * (`FileSpec`/`KeySpec`, the DUP/DESCENDING/EXTTYPE bits, 1-based
 * `position`) against a live engine for shapes `cmd_create` never tried, and
 * `insert`/`dump` prove the round trip on whatever it built -- v6 or not.
 * What it does NOT do is tell create.rs what bytes to write for a v5 file,
 * because this engine cannot be made to write one; that measurement is the
 * five `.VIR` files above, read directly with a hex dump, not through this
 * program.
 *
 * BUILD
 *   i686-w64-mingw32-gcc -O2 -o crtprobe.exe crtprobe.c
 * (see build.sh's btrvprobe.exe rule; this one is not wired into build.sh
 * because it is a measurement tool, not a fixture generator anything else
 * depends on -- build it by hand when using it.)
 *
 * USAGE
 *   crtprobe create <path> <reclen> <pagesize> <cflags> <prealloc> <overwrite:0|1> \
 *            <nsegs> [pos len type flags]...
 *     <pos>   1-based byte offset within the record (matches the real
 *             KeySpec.position -- see the ABI note in btrvprobe.c)
 *     <flags> the raw KeySpec.flags word: DUP=1 MODIFY=2 MANUAL=8 SEGMENT=0x10
 *             DESCENDING=0x40 EXTTYPE=0x100 NULLKEY=0x200 (OR them yourself;
 *             SEGMENT must be set on every segment but a key's last)
 *   crtprobe insert <path> <hex-bytes>
 *     one record, raw hex, no separators (e.g. "0100000000000000")
 *   crtprobe dumpraw <path> <bytes>
 *     print the first <bytes> of the file AS THE ENGINE SEES IT -- opened
 *     and STAT'd first so a stale Microkernel cache is forced to notice the
 *     path, then read back with plain file I/O. Diagnostic only; prefer
 *     reading the file directly from the wine work dir for real measurement,
 *     since this still goes through whatever the OS's page cache holds.
 */
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define B_OPEN       0
#define B_CLOSE      1
#define B_INSERT     2
#define B_GET_FIRST 12
#define B_CREATE    14
#define B_STAT      15
#define B_STOP      25

#define MODE_NORMAL     0
#define MODE_READ_ONLY (-2)

#define ST_OK 0

#define POSBLK_SIZE  128
#define DATA_SIZE   32768
#define KEY_SIZE      256
#define MAX_SEGS       24

typedef int (__stdcall *BTRCALL_FN)(WORD op, void *posblk, void *databuf,
                                    DWORD *datalen, void *keybuf,
                                    BYTE keylen, char keynum);
static BTRCALL_FN btrcall;

/* Identical layout to btrvprobe.c's FileSpec/KeySpec -- see that file's own
 * comment for how each field was pinned down. Redeclared here rather than
 * shared through a header because neither program has one; keeping both
 * copies is one `#pragma pack` block each, not worth a build-system change
 * for. */
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
    case 4:  return "key value not found";
    case 5:  return "duplicate key value";
    case 6:  return "invalid key number";
    case 9:  return "end of file";
    case 11: return "invalid filename";
    case 12: return "file not found";
    case 18: return "disk full";
    case 20: return "record manager inactive";
    case 22: return "data buffer too short";
    case 24: return "page size error";
    case 30: return "not a Btrieve file";
    case 46: return "access denied";
    case 54: return "variable page error";
    case 62: return "incorrect descriptor";
    case 63: return "invalid key segment number/count";
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

/*
 * create: build a FileSpec + KeySpec[] buffer entirely from argv and issue
 * B_CREATE. Every field `cmd_create` in btrvprobe.c hardcoded is a parameter
 * here, so a shell loop can vary one at a time.
 */
static void cmd_create(int argc, char **argv)
{
    char posblk[POSBLK_SIZE];
    char keybuf[KEY_SIZE];
    unsigned char data[sizeof(FileSpec) + MAX_SEGS * sizeof(KeySpec)];
    FileSpec *fs = (FileSpec *)data;
    DWORD dlen;
    int st, nsegs, i, overwrite;
    const char *path;

    if (argc < 10) {
        fprintf(stderr,
            "usage: crtprobe create <path> <reclen> <pagesize> <cflags> "
            "<prealloc> <overwrite:0|1> <nsegs> [pos len type flags]...\n");
        exit(2);
    }
    path = argv[2];
    nsegs = atoi(argv[8]);
    if (nsegs < 1 || nsegs > MAX_SEGS) {
        fprintf(stderr, "FAIL: nsegs %d out of range 1..%d\n", nsegs, MAX_SEGS);
        exit(2);
    }
    if (argc != 9 + nsegs * 4) {
        fprintf(stderr, "FAIL: %d segments needs %d more args, got %d\n",
                nsegs, nsegs * 4, argc - 9);
        exit(2);
    }

    memset(posblk, 0, sizeof posblk);
    memset(data, 0, sizeof data);
    memset(keybuf, 0, sizeof keybuf);
    strncpy(keybuf, path, sizeof keybuf - 1);

    fs->reclen = (WORD)strtoul(argv[3], NULL, 0);
    fs->pagesize = (WORD)strtoul(argv[4], NULL, 0);
    /* cflags (argv[5]) is DFACF_* -- accepted but not yet placed anywhere:
     * every FileSpec field this struct has is accounted for above, and
     * `indexes_raw` is the only one `cmd_create` ever set on a real call.
     * Kept as a parameter for a future probe run that needs it, refused
     * loudly here rather than silently ignored forever. */
    if (strtoul(argv[5], NULL, 0) != 0) {
        fprintf(stderr, "FAIL: cflags != 0 is not wired to anything in this probe yet\n");
        exit(2);
    }
    if (strtoul(argv[6], NULL, 0) != 0) {
        fprintf(stderr, "FAIL: prealloc != 0 is not wired to anything in this probe yet\n");
        exit(2);
    }
    overwrite = atoi(argv[7]);
    fs->indexes_raw = (WORD)nsegs; /* overwritten below if any SEGMENT bit clears it down to key count */

    {
        int nkeys = 0;
        KeySpec *ks = (KeySpec *)(data + sizeof(FileSpec));
        for (i = 0; i < nsegs; i++) {
            int base = 9 + i * 4;
            ks[i].position = (WORD)strtoul(argv[base + 0], NULL, 0);
            ks[i].length = (WORD)strtoul(argv[base + 1], NULL, 0);
            ks[i].ext_type = (BYTE)strtoul(argv[base + 2], NULL, 0);
            ks[i].flags = (WORD)strtoul(argv[base + 3], NULL, 0);
            if (!(ks[i].flags & 0x0010)) /* SEGMENT bit clear -> last segment of a key */
                nkeys++;
        }
        fs->indexes_raw = (WORD)nkeys;
    }

    dlen = (DWORD)(sizeof(FileSpec) + (unsigned)nsegs * sizeof(KeySpec));
    st = btrcall(B_CREATE, posblk, data, &dlen, keybuf,
                (BYTE)(strlen(keybuf) + 1), (char)(overwrite ? -1 : 0));
    if (st != ST_OK)
        die("create", st);
    printf("created %s: reclen=%u pagesize=%u keys=%u segments=%d\n",
           path, fs->reclen, fs->pagesize, fs->indexes_raw, nsegs);

    { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }
}

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* insert: one record, raw hex on argv, no separators. */
static void cmd_insert(const char *path, const char *hex)
{
    char posblk[POSBLK_SIZE];
    unsigned char record[DATA_SIZE];
    unsigned char keybuf[KEY_SIZE];
    DWORD dlen;
    size_t len, i;
    int st;

    len = strlen(hex);
    if (len % 2 != 0 || len / 2 > sizeof record) {
        fprintf(stderr, "FAIL: bad hex length %zu\n", len);
        exit(2);
    }
    for (i = 0; i < len / 2; i++) {
        int hi = hexval(hex[i * 2]), lo = hexval(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) {
            fprintf(stderr, "FAIL: bad hex digit at byte %zu\n", i);
            exit(2);
        }
        record[i] = (unsigned char)((hi << 4) | lo);
    }

    st = open_file(posblk, path, MODE_NORMAL);
    if (st != ST_OK)
        die("open", st);

    dlen = (DWORD)(len / 2);
    memset(keybuf, 0, sizeof keybuf);
    st = btrcall(B_INSERT, posblk, record, &dlen, keybuf, sizeof keybuf - 1, (char)0);
    printf("insert: status %d (%s)\n", st, status_name(st));

    { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }
    if (st != ST_OK)
        exit(1);
}

/* dumpraw: open+STAT (forces the Microkernel to notice this path rather than
 * serve a stale cache entry, the same reason sweep.sh gives every file a
 * fresh name), then read `bytes` off disk with plain file I/O and print hex.
 * This is NOT a reliable way to see what the engine just wrote for a file it
 * still has open -- see the file header comment -- it is here only for a
 * quick sanity check right after `create`, before the process (and the
 * Microkernel's per-path cache with it) has had any reason to flush. */
static void cmd_dumpraw(const char *path, int bytes)
{
    char posblk[POSBLK_SIZE];
    unsigned char stat_data[512];
    DWORD dlen = sizeof stat_data;
    FILE *fp;
    unsigned char *buf;
    int n, i;

    if (open_file(posblk, path, MODE_READ_ONLY) == ST_OK) {
        btrcall(B_STAT, posblk, stat_data, &dlen, NULL, 0, (char)-1);
        { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }
    }

    fp = fopen(path, "rb");
    if (!fp) {
        fprintf(stderr, "FAIL: cannot open %s for raw read\n", path);
        exit(1);
    }
    buf = malloc((size_t)bytes);
    n = (int)fread(buf, 1, (size_t)bytes, fp);
    fclose(fp);
    for (i = 0; i < n; i++)
        printf("%02x", buf[i]);
    printf("\n");
    free(buf);
}

int main(int argc, char **argv)
{
    HMODULE dll;
    const char *cmd;

    if (argc < 2) {
        fprintf(stderr,
            "usage: crtprobe <create|insert|dumpraw> ...\n"
            "  create <path> <reclen> <pagesize> <cflags> <prealloc> "
            "<overwrite:0|1> <nsegs> [pos len type flags]...\n"
            "  insert <path> <hex-bytes>\n"
            "  dumpraw <path> <bytes>\n");
        return 2;
    }
    cmd = argv[1];

    dll = LoadLibraryA("WBTRV32.DLL");
    if (!dll) {
        fprintf(stderr, "FAIL: cannot load WBTRV32.DLL (error %lu)\n",
                (unsigned long)GetLastError());
        return 1;
    }
    btrcall = (BTRCALL_FN)GetProcAddress(dll, "BTRCALL");
    if (!btrcall) {
        fprintf(stderr, "FAIL: WBTRV32.DLL exports no BTRCALL\n");
        return 1;
    }

    if (!strcmp(cmd, "create"))
        cmd_create(argc, argv);
    else if (!strcmp(cmd, "insert")) {
        if (argc < 4) { fprintf(stderr, "FAIL: insert needs a path and hex bytes\n"); return 2; }
        cmd_insert(argv[2], argv[3]);
    } else if (!strcmp(cmd, "dumpraw")) {
        if (argc < 4) { fprintf(stderr, "FAIL: dumpraw needs a path and byte count\n"); return 2; }
        cmd_dumpraw(argv[2], atoi(argv[3]));
    } else {
        fprintf(stderr, "FAIL: unknown command %s\n", cmd);
        return 2;
    }

    { DWORD d = 0; char pb[POSBLK_SIZE] = {0}; btrcall(B_STOP, pb, NULL, &d, NULL, 0, 0); }
    return 0;
}
