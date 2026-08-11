/*
 * ppprobe -- THROWAWAY research probe, NOT part of the tree under test.
 *
 * Drives genuine Btrieve 6.15 (under Wine) to mint files of controlled
 * page size and record count, so the "PP" allocation pages that appear once
 * a v6 file (6.15's default B_CREATE output) grows past a couple of pages
 * can be measured by diffing files of increasing size.
 *
 * Modelled on tools/btrieve-oracle/btrvprobe.c and
 * .scratch-task5-research/varprobe.c (same struct layouts, same ABI notes:
 * the fourth BTRCALL parameter is a length POINTER and the engine reads only
 * its low 16 bits). Neither of those files is edited; this is independent.
 */
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define B_OPEN        0
#define B_CLOSE       1
#define B_INSERT      2
#define B_UPDATE      3
#define B_DELETE      4
#define B_GET_NEXT    6
#define B_GET_FIRST  12
#define B_CREATE     14
#define B_STAT       15
#define B_STOP       25

#define POSBLK_SIZE 128
#define DATA_SIZE 32768
#define KEY_SIZE    256

typedef int (__stdcall *BTRCALL_FN)(WORD op, void *posblk, void *databuf,
                                    DWORD *datalen, void *keybuf,
                                    BYTE keylen, char keynum);
static BTRCALL_FN btrcall;

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
    case 4:  return "key value not found";
    case 5:  return "duplicate key value";
    case 9:  return "end of file";
    case 18: return "disk full";
    case 24: return "page size error";
    case 30: return "not a Btrieve file";
    case 84: return "record too long";
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

/* create <path> <reclen> <pagesize> <keyflags-hex> */
static void cmd_create(const char *path, WORD reclen, WORD pagesize, WORD keyflags)
{
    char posblk[POSBLK_SIZE];
    char keybuf[KEY_SIZE];
    unsigned char data[sizeof(FileSpec) + sizeof(KeySpec)];
    FileSpec *fs = (FileSpec *)data;
    KeySpec *ks = (KeySpec *)(data + sizeof(FileSpec));
    DWORD dlen = sizeof data;
    int st;

    memset(posblk, 0, sizeof posblk);
    memset(data, 0, sizeof data);
    memset(keybuf, 0, sizeof keybuf);
    strncpy(keybuf, path, sizeof keybuf - 1);

    fs->reclen = reclen;
    fs->pagesize = pagesize;
    fs->indexes_raw = 1;

    ks->position = 1;
    ks->length = 4;
    ks->flags = (WORD)(0x0100 | keyflags); /* EXTTYPE always set, plus caller's bits */
    ks->ext_type = 0x0e; /* unsigned binary */

    st = btrcall(B_CREATE, posblk, data, &dlen, keybuf,
                (BYTE)(strlen(keybuf) + 1), -1 /* overwrite if present */);
    if (st != 0)
        die("create", st);
    { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }
    printf("create %s reclen=%u pagesize=%u: OK\n", path, reclen, pagesize);
}

/* fill <path> <count> <reclen> [start]: insert `count` records, 4-byte
 * ascending key at offset 0 starting at `start` (default 0), filler 0xAA
 * thereafter, so the file grows to `count` more records. `start` lets a
 * caller insert one record per process invocation without colliding on a
 * unique key across invocations. */
static void cmd_fill(const char *path, DWORD count, WORD reclen, DWORD start)
{
    char posblk[POSBLK_SIZE];
    unsigned char *record;
    unsigned char keybuf[KEY_SIZE];
    DWORD dlen, i;
    int st;
    unsigned failures = 0;

    st = open_file(posblk, path, 0);
    if (st != 0)
        die("open", st);

    record = malloc(reclen);
    for (i = start; i < start + count; i++) {
        record[0] = (unsigned char)(i & 0xff);
        record[1] = (unsigned char)((i >> 8) & 0xff);
        record[2] = (unsigned char)((i >> 16) & 0xff);
        record[3] = (unsigned char)((i >> 24) & 0xff);
        if (reclen > 4)
            memset(record + 4, 0xAA, reclen - 4);

        dlen = reclen;
        memset(keybuf, 0, sizeof keybuf);
        st = btrcall(B_INSERT, posblk, record, &dlen, keybuf, sizeof keybuf - 1, 0);
        if (st != 0) {
            failures++;
            if (failures < 5)
                fprintf(stderr, "insert %lu: status %d (%s)\n",
                        (unsigned long)i, st, status_name(st));
        }
    }
    free(record);

    { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }
    printf("fill %s count=%lu reclen=%u start=%lu: %u failures\n",
           path, (unsigned long)count, reclen, (unsigned long)start, failures);
}

/* touch <path>: GET_FIRST, flip a filler byte, UPDATE, CLOSE -- to see which
 * pages change (and which shadow copy) on an in-place record modification. */
static void cmd_touch(const char *path)
{
    char posblk[POSBLK_SIZE];
    static unsigned char record[DATA_SIZE];
    unsigned char keybuf[KEY_SIZE];
    DWORD dlen;
    int st;

    st = open_file(posblk, path, 0);
    if (st != 0)
        die("open", st);

    dlen = DATA_SIZE;
    memset(keybuf, 0, sizeof keybuf);
    st = btrcall(B_GET_FIRST, posblk, record, &dlen, keybuf, sizeof keybuf - 1, 0);
    if (st != 0)
        die("get_first", st);

    if (dlen > 4)
        record[4] ^= 0xff; /* flip the first filler byte */

    st = btrcall(B_UPDATE, posblk, record, &dlen, keybuf, sizeof keybuf - 1, 0);
    if (st != 0)
        die("update", st);

    { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }
    printf("touch %s: OK (dlen=%lu)\n", path, (unsigned long)dlen);
}

static void cmd_stat(const char *path)
{
    char posblk[POSBLK_SIZE];
    static unsigned char data[DATA_SIZE];
    char keybuf[KEY_SIZE];
    DWORD dlen = DATA_SIZE;
    int st;
    FileSpec *fs = (FileSpec *)data;

    st = open_file(posblk, path, -2);
    if (st != 0)
        die("open for stat", st);
    memset(keybuf, 0, sizeof keybuf);
    st = btrcall(B_STAT, posblk, data, &dlen, keybuf, sizeof keybuf - 1, -1);
    if (st != 0)
        die("stat", st);
    printf("stat %s: reclen=%u pagesize=%u records=%lu flags=0x%04x\n",
           path, fs->reclen, fs->pagesize, (unsigned long)fs->records, fs->flags);
    { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }
}

int main(int argc, char **argv)
{
    HMODULE dll;
    const char *cmd, *path;

    if (argc < 3) {
        fprintf(stderr,
            "usage: ppprobe create <path> <reclen> <pagesize> [keyflags-hex]\n"
            "       ppprobe fill <path> <count> <reclen>\n"
            "       ppprobe touch <path>\n"
            "       ppprobe stat <path>\n");
        return 2;
    }
    cmd = argv[1];
    path = argv[2];

    dll = LoadLibraryA("WBTRV32.DLL");
    if (!dll) { fprintf(stderr, "FAIL: cannot load WBTRV32.DLL\n"); return 1; }
    btrcall = (BTRCALL_FN)GetProcAddress(dll, "BTRCALL");
    if (!btrcall) { fprintf(stderr, "FAIL: no BTRCALL export\n"); return 1; }

    if (!strcmp(cmd, "create")) {
        if (argc < 5) { fprintf(stderr, "create needs reclen pagesize\n"); return 2; }
        cmd_create(path, (WORD)atoi(argv[3]), (WORD)atoi(argv[4]),
                   argc > 5 ? (WORD)strtoul(argv[5], NULL, 16) : 0);
    } else if (!strcmp(cmd, "fill")) {
        if (argc < 5) { fprintf(stderr, "fill needs count reclen [start]\n"); return 2; }
        cmd_fill(path, (DWORD)strtoul(argv[3], NULL, 10), (WORD)atoi(argv[4]),
                 argc > 5 ? (DWORD)strtoul(argv[5], NULL, 10) : 0);
    } else if (!strcmp(cmd, "touch")) {
        cmd_touch(path);
    } else if (!strcmp(cmd, "stat")) {
        cmd_stat(path);
    } else {
        fprintf(stderr, "FAIL: unknown command %s\n", cmd);
        return 2;
    }

    { DWORD d = 0; char pb[POSBLK_SIZE] = {0}; btrcall(B_STOP, pb, NULL, &d, NULL, 0, 0); }
    return 0;
}
