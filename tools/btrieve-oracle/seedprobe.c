/*
 * seedprobe -- THROWAWAY research probe. Create a fixed-length file with one
 * unique 4-byte key and insert N records, all within ONE process/session,
 * for docs/plans/2026-08-12-btrieve-finish.md's lock measurement.
 *
 * WHY THIS EXISTS RATHER THAN A SHELL LOOP OF `crtprobe insert`
 *
 * A shell loop spawning one fresh `wine crtprobe.exe insert ...` process per
 * record (24 of them, sequentially) was measured to WEDGE on this host: the
 * 24th invocation sat with zero CPU and zero progress for over three minutes
 * before being killed by hand. This is the same failure sweep.sh's own
 * comment already documents ("running other wine clients against it while a
 * sweep is in flight was observed to wedge one invocation indefinitely").
 * Nothing else was running against the prefix at the time, so the trigger
 * here looks like repeated fresh-process spawn/teardown against the shared
 * Microkernel, not concurrent access -- one process that opens, inserts
 * everything, and exits once does not hit it.
 *
 * Geometry: reclen 32, pagesize 512, one 4-byte unique unsigned-binary key at
 * record byte 1 (1-based), same shape xactprobe.c/crtprobe.c use elsewhere in
 * this directory. Record layout: 4-byte LE key, then 28 bytes of a repeated
 * tag byte (0xA0 + key, wrapped at 0xFF) -- enough to tell records apart in a
 * hex dump without decoding anything.
 *
 * USAGE
 *   seedprobe.exe <path> <count>
 */
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define B_OPEN    0
#define B_CLOSE   1
#define B_INSERT  2
#define B_CREATE 14
#define B_STOP   25

#define POSBLK_SIZE 128
#define RECLEN 32
#define KEY_SIZE 256

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

static void die(const char *what, int st)
{
    fprintf(stderr, "FAIL %s: status %d\n", what, st);
    exit(1);
}

int main(int argc, char **argv)
{
    HMODULE dll;
    const char *path;
    int count, i;
    char posblk[POSBLK_SIZE];
    char keybuf[KEY_SIZE];
    unsigned char data[sizeof(FileSpec) + sizeof(KeySpec)];
    FileSpec *fs = (FileSpec *)data;
    KeySpec *ks = (KeySpec *)(data + sizeof(FileSpec));
    DWORD dlen;
    int st;

    if (argc < 3) {
        fprintf(stderr, "usage: seedprobe <path> <count>\n");
        return 2;
    }
    path = argv[1];
    count = atoi(argv[2]);

    dll = LoadLibraryA("WBTRV32.DLL");
    if (!dll) { fprintf(stderr, "FAIL: cannot load WBTRV32.DLL\n"); return 1; }
    btrcall = (BTRCALL_FN)GetProcAddress(dll, "BTRCALL");
    if (!btrcall) { fprintf(stderr, "FAIL: no BTRCALL export\n"); return 1; }

    memset(posblk, 0, sizeof posblk);
    memset(data, 0, sizeof data);
    memset(keybuf, 0, sizeof keybuf);
    strncpy(keybuf, path, sizeof keybuf - 1);

    fs->reclen = RECLEN;
    fs->pagesize = 512;
    fs->indexes_raw = 1;
    fs->flags = 0;
    ks->position = 1;
    ks->length = 4;
    ks->flags = 0x0100; /* EXTTYPE only: unique, ascending */
    ks->ext_type = 0x0e; /* unsigned binary */

    dlen = sizeof data;
    st = btrcall(B_CREATE, posblk, data, &dlen, keybuf,
                (BYTE)(strlen(keybuf) + 1), (char)0);
    if (st != 0)
        die("create", st);
    { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }

    memset(posblk, 0, sizeof posblk);
    memset(keybuf, 0, sizeof keybuf);
    strncpy(keybuf, path, sizeof keybuf - 1);
    dlen = 0;
    st = btrcall(B_OPEN, posblk, NULL, &dlen, keybuf,
                (BYTE)(strlen(keybuf) + 1), 0);
    if (st != 0)
        die("open", st);

    for (i = 0; i < count; i++) {
        unsigned char record[RECLEN];
        unsigned char ikeybuf[KEY_SIZE];
        unsigned char tag = (unsigned char)(0xA0 + (i & 0x5F));
        unsigned j;

        record[0] = (unsigned char)(i & 0xff);
        record[1] = (unsigned char)((i >> 8) & 0xff);
        record[2] = (unsigned char)((i >> 16) & 0xff);
        record[3] = (unsigned char)((i >> 24) & 0xff);
        for (j = 4; j < RECLEN; j++)
            record[j] = tag;

        memset(ikeybuf, 0, sizeof ikeybuf);
        dlen = RECLEN;
        st = btrcall(B_INSERT, posblk, record, &dlen, ikeybuf, sizeof ikeybuf - 1, 0);
        if (st != 0) {
            fprintf(stderr, "FAIL: insert record %d: status %d\n", i, st);
            return 1;
        }
    }

    { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }
    printf("seeded %s with %d records\n", path, count);

    { DWORD d = 0; char pb[POSBLK_SIZE] = {0}; btrcall(B_STOP, pb, NULL, &d, NULL, 0, 0); }
    return 0;
}
