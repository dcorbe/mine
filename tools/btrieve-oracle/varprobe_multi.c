/*
 * varprobe_multi -- THROWAWAY research probe, forked from varprobe.c.
 * Inserts N variable-length records with distinct keys and a given total
 * size each, to grow a v6 file far enough to force more than one 'PP'
 * allocation-table page, and to see whether the fragment continuation
 * pointer's page component tracks physical page number through that growth.
 */
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>

#define B_OPEN     0
#define B_CLOSE    1
#define B_INSERT   2
#define B_DELETE   4
#define B_GET_EQUAL 5
#define B_CREATE  14
#define B_STAT    15
#define B_STOP    25

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

static void die(const char *what, int st) {
    fprintf(stderr, "FAIL %s: status %d\n", what, st);
    exit(1);
}

static void create_file(const char *path, WORD reclen, WORD pagesize, WORD flags) {
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
    fs->flags = flags;

    ks->position = 1;
    ks->length = 4;
    ks->flags = 0x0100;
    ks->ext_type = 0x0e;

    st = btrcall(B_CREATE, posblk, data, &dlen, keybuf,
                (BYTE)(strlen(keybuf) + 1), -1);
    if (st != 0)
        die("create", st);
    { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }
}

static int open_file(char *posblk, const char *path) {
    char keybuf[KEY_SIZE];
    DWORD dlen = 0;
    memset(posblk, 0, POSBLK_SIZE);
    memset(keybuf, 0, sizeof keybuf);
    strncpy(keybuf, path, sizeof keybuf - 1);
    return btrcall(B_OPEN, posblk, NULL, &dlen, keybuf,
                   (BYTE)(strlen(keybuf) + 1), 0);
}

/* Insert one record: key = `key` (4-byte LE at position 0), body filled with
 * a marker keyed by `key` so different records' bodies are distinguishable:
 * byte i (i>=4) = 0x80 + ((key*7 + i) % 32). Total length `total`. */
static int insert_one(char *posblk, DWORD key, WORD total) {
    unsigned char record[DATA_SIZE];
    unsigned char keybuf[KEY_SIZE];
    DWORD dlen;
    unsigned i;
    int st;

    memset(record, 0, sizeof record);
    record[0] = (unsigned char)(key & 0xff);
    record[1] = (unsigned char)((key >> 8) & 0xff);
    record[2] = (unsigned char)((key >> 16) & 0xff);
    record[3] = (unsigned char)((key >> 24) & 0xff);
    for (i = 4; i < total; i++)
        record[i] = (unsigned char)(0x80 + ((key * 7 + i) % 32));

    dlen = total;
    memset(keybuf, 0, sizeof keybuf);
    st = btrcall(B_INSERT, posblk, record, &dlen, keybuf, sizeof keybuf - 1, 0);
    return st;
}

/* Delete the record whose key equals `key` (B_GET_EQUAL then B_DELETE). */
static int delete_key(char *posblk, DWORD key) {
    unsigned char databuf[DATA_SIZE];
    unsigned char keybuf[KEY_SIZE];
    DWORD dlen;
    int st;

    memset(keybuf, 0, sizeof keybuf);
    keybuf[0] = (unsigned char)(key & 0xff);
    keybuf[1] = (unsigned char)((key >> 8) & 0xff);
    keybuf[2] = (unsigned char)((key >> 16) & 0xff);
    keybuf[3] = (unsigned char)((key >> 24) & 0xff);

    dlen = DATA_SIZE;
    st = btrcall(B_GET_EQUAL, posblk, databuf, &dlen, keybuf, 4, 0);
    if (st != 0)
        return st;
    dlen = 0;
    return btrcall(B_DELETE, posblk, NULL, &dlen, NULL, 0, 0);
}

int main(int argc, char **argv) {
    HMODULE dll;
    const char *path, *mode;
    WORD reclen, pagesize, flags, total;
    DWORD count, i;
    char posblk[POSBLK_SIZE];
    int st;

    /* modes:
     *   create <path> <reclen> <pagesize> <flags>
     *   insertN <path> <count> <total> <startkey>
     *   delete <path> <key>
     *   reinsert <path> <key> <total>
     */
    if (argc < 3) {
        fprintf(stderr, "usage: varprobe_multi <mode> <path> ...\n");
        return 2;
    }
    mode = argv[1];
    path = argv[2];

    dll = LoadLibraryA("WBTRV32.DLL");
    if (!dll) { fprintf(stderr, "FAIL: cannot load WBTRV32.DLL\n"); return 1; }
    btrcall = (BTRCALL_FN)GetProcAddress(dll, "BTRCALL");
    if (!btrcall) { fprintf(stderr, "FAIL: no BTRCALL export\n"); return 1; }

    if (strcmp(mode, "create") == 0) {
        reclen = (WORD)atoi(argv[3]);
        pagesize = (WORD)atoi(argv[4]);
        flags = (WORD)strtoul(argv[5], NULL, 0);
        create_file(path, reclen, pagesize, flags);
        printf("created %s reclen=%u pagesize=%u flags=0x%x\n", path, reclen, pagesize, flags);
    } else if (strcmp(mode, "insertN") == 0) {
        count = (DWORD)atoi(argv[3]);
        total = (WORD)atoi(argv[4]);
        DWORD startkey = (DWORD)atoi(argv[5]);
        st = open_file(posblk, path);
        if (st != 0) die("open", st);
        for (i = 0; i < count; i++) {
            st = insert_one(posblk, startkey + i, total);
            if (st != 0) {
                fprintf(stderr, "insert key=%lu: status %d\n", (unsigned long)(startkey + i), st);
            }
        }
        printf("inserted %lu records\n", (unsigned long)count);
        { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }
    } else if (strcmp(mode, "delete") == 0) {
        DWORD key = (DWORD)atoi(argv[3]);
        st = open_file(posblk, path);
        if (st != 0) die("open", st);
        st = delete_key(posblk, key);
        printf("delete key=%lu: status %d\n", (unsigned long)key, st);
        { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }
    } else if (strcmp(mode, "reinsert") == 0) {
        DWORD key = (DWORD)atoi(argv[3]);
        total = (WORD)atoi(argv[4]);
        st = open_file(posblk, path);
        if (st != 0) die("open", st);
        st = insert_one(posblk, key, total);
        printf("reinsert key=%lu total=%u: status %d\n", (unsigned long)key, total, st);
        { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }
    } else {
        fprintf(stderr, "unknown mode %s\n", mode);
        return 2;
    }

    { DWORD d = 0; char pb[POSBLK_SIZE] = {0}; btrcall(B_STOP, pb, NULL, &d, NULL, 0, 0); }
    return 0;
}
