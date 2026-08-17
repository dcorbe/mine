/*
 * varfree -- where does a Btrieve file keep the head of its variable
 * free-space chain, ON DISK?
 *
 * Forked from updprobe.c, which supplies the WCCTEXT-shaped variable rig.
 *
 * # Why this probe has to exist
 *
 * W32MKDE's allocator (FUN_00420da0, :19340-19344) reads that head as
 *
 *     local_3c = (uint *)(local_2c + 0x24)
 *
 * and the design doc's section 2.1a shows `local_2c` is the engine's
 * IN-MEMORY file block, not the on-disk file control record:
 *
 *   - on-disk 0x1c is `at::RECORDS_LOW`, the record count, not the general
 *     free-page chain the same routine reads at `local_2c + 0x1c`;
 *   - on-disk 0x112 of a genuine v6 variable file reads 2, not a version
 *     word at or above 0x600, which is what `local_28 + 0x112` is compared
 *     against.
 *
 * So the on-disk address has to be found the way fcr 0x9c was found for the
 * v6 record free list (docs/2026-08-16-v6-update-delete-oracle.md): fill one
 * variable page, spill onto a second, and diff the snapshots.
 *
 * # The rig
 *
 * reclen 22, **pagesize 512**, flags 0x0001 (variable), one unique 4-byte
 * unsigned-binary key at record byte 1. 512 rather than WCCTEXT's 2048 so
 * that a variable page fills in two inserts and spills on the third -- a
 * 2048-byte page needs ten and buries the signal in unrelated churn.
 *
 * A 512-byte variable page has 12 bytes of header and a 2-byte entry per
 * fragment growing down from the end, so roughly 490 bytes of usable body.
 * Bodies of 200 bytes therefore go two to a page.
 *
 * # Commands
 *
 * Every invocation opens, does exactly one operation, closes, and ends in
 * B_STOP, so each snapshot is what reached disk rather than what the
 * Microkernel was still holding.
 *
 *   varfree create <path>
 *   varfree insert <path> <key> <total> <fillbyte>
 *   varfree get    <path> <key>
 *
 * **Never reuse a path across runs.** The Microkernel caches pages by path
 * across processes and will serve the previous file's pages for a new one;
 * tools/btrieve-oracle/sweep.sh has the transcript of that going wrong.
 */
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define B_OPEN       0
#define B_CLOSE      1
#define B_INSERT     2
#define B_DELETE     4
#define B_GET_EQUAL  5
#define B_CREATE    14
#define B_STOP      25

#define POSBLK_SIZE 128
#define DATA_SIZE 32768   /* must stay < 65536; the engine reads only the low
                             16 bits of the length pointer -- btrvprobe.c's
                             ABI NOTE. */
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
    case 3:  return "file not open";
    case 4:  return "key value not found";
    case 5:  return "duplicate key value";
    case 8:  return "invalid positioning";
    case 9:  return "end of file";
    case 11: return "invalid filename";
    case 12: return "file not found";
    case 18: return "disk full";
    case 22: return "data buffer too short";
    case 24: return "page size error";
    case 30: return "not a Btrieve file";
    case 46: return "access denied";
    case 54: return "variable page error";
    default: return "?";
    }
}

static void die(const char *what, int st)
{
    fprintf(stderr, "FAIL %s: status %d (%s)\n", what, st, status_name(st));
    exit(1);
}

static void cmd_create(const char *path)
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

    fs->reclen = 22;
    fs->pagesize = 512;
    fs->indexes_raw = 1;
    fs->flags = 0x0001;   /* bit 0 -- variable-length records */

    ks->position = 1;
    ks->length = 4;
    ks->flags = 0x0100;   /* EXTTYPE only: unique, ascending */
    ks->ext_type = 0x0e;  /* unsigned binary */

    st = btrcall(B_CREATE, posblk, data, &dlen, keybuf,
                 (BYTE)(strlen(keybuf) + 1), (char)0);
    if (st != 0)
        die("create", st);
    printf("created %s reclen=22 pagesize=512 flags=0x0001 (variable)\n", path);
    { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }
}

/* The same rig, but with the key permitting DUPLICATES -- WGSGEN2.DAT's
 * shape, which is what stops MajorMUD's boot once variable-length writes
 * work. Inserting several records under one key value is what shows where
 * the chain joining them lives and what the index entry carries.
 *
 * Attribute 0x0001 is DUPLICATE; 0x0100 is EXTTYPE, as in cmd_create. */
static void cmd_create_dup(const char *path)
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

    fs->reclen = 22;
    fs->pagesize = 512;
    fs->indexes_raw = 1;
    fs->flags = 0x0001;   /* variable-length records */

    ks->position = 1;
    ks->length = 4;
    ks->flags = 0x0101;   /* DUPLICATE | EXTTYPE */
    ks->ext_type = 0x0e;  /* unsigned binary */

    st = btrcall(B_CREATE, posblk, data, &dlen, keybuf,
                 (BYTE)(strlen(keybuf) + 1), (char)0);
    if (st != 0)
        die("create_dup", st);
    printf("created %s reclen=22 pagesize=512 variable, key 0 permits duplicates\n",
           path);
    { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }
}

static int open_file(char *posblk, const char *path)
{
    char keybuf[KEY_SIZE];
    DWORD dlen = 0;
    memset(posblk, 0, POSBLK_SIZE);
    memset(keybuf, 0, sizeof keybuf);
    strncpy(keybuf, path, sizeof keybuf - 1);
    return btrcall(B_OPEN, posblk, NULL, &dlen, keybuf,
                   (BYTE)(strlen(keybuf) + 1), 0);
}

/* Key at [0..4), 0xEE across the rest of the fixed part, and `fill` for the
 * whole variable body. One repeated byte per record, so a fragment's bytes
 * name the record they came from at a glance in a hex dump. Never zero, so
 * any zero found later is provably not something this probe wrote. */
static void fill_record(unsigned char *record, DWORD key, WORD total,
                        unsigned char fill)
{
    unsigned i;
    record[0] = (unsigned char)(key & 0xff);
    record[1] = (unsigned char)((key >> 8) & 0xff);
    record[2] = (unsigned char)((key >> 16) & 0xff);
    record[3] = (unsigned char)((key >> 24) & 0xff);
    for (i = 4; i < 22 && i < total; i++)
        record[i] = 0xEE;
    for (i = 22; i < total; i++)
        record[i] = fill;
}

static void cmd_insert(const char *path, DWORD key, WORD total,
                       unsigned char fill)
{
    char posblk[POSBLK_SIZE];
    unsigned char record[DATA_SIZE];
    unsigned char keybuf[KEY_SIZE];
    DWORD dlen;
    int st;

    if (total < 22) {
        fprintf(stderr, "FAIL: total %u is shorter than the 22-byte fixed part\n",
                total);
        exit(2);
    }

    st = open_file(posblk, path);
    if (st != 0)
        die("open", st);

    memset(record, 0, sizeof record);
    fill_record(record, key, total, fill);

    dlen = total;
    memset(keybuf, 0, sizeof keybuf);
    st = btrcall(B_INSERT, posblk, record, &dlen, keybuf, sizeof keybuf - 1, 0);
    printf("insert key=%lu total=%u body=%u fill=0x%02x status=%d (%s)\n",
           (unsigned long)key, total, (unsigned)(total - 22), fill,
           st, status_name(st));
    if (st != 0)
        die("insert", st);

    { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }
}

/* Read a record back whole, so a ladder can prove the chain still resolves
 * after every step rather than only that the bytes moved. */
static void cmd_get(const char *path, DWORD key)
{
    static unsigned char data[DATA_SIZE];
    char posblk[POSBLK_SIZE];
    unsigned char keybuf[KEY_SIZE];
    DWORD dlen;
    int st;

    st = open_file(posblk, path);
    if (st != 0)
        die("open", st);

    memset(keybuf, 0, sizeof keybuf);
    keybuf[0] = (unsigned char)(key & 0xff);
    keybuf[1] = (unsigned char)((key >> 8) & 0xff);
    keybuf[2] = (unsigned char)((key >> 16) & 0xff);
    keybuf[3] = (unsigned char)((key >> 24) & 0xff);

    dlen = DATA_SIZE;
    memset(data, 0, sizeof data);
    st = btrcall(B_GET_EQUAL, posblk, data, &dlen, keybuf, 4, 0);
    if (st != 0) {
        printf("get key=%lu: status=%d (%s)\n",
               (unsigned long)key, st, status_name(st));
    } else {
        printf("get key=%lu: status=0 (OK) datalen=%lu body_byte=0x%02x\n",
               (unsigned long)key, (unsigned long)dlen,
               dlen > 22 ? data[22] : 0);
    }

    { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }
}

/* Delete the record for `key`. A delete is what puts a SECOND page on the
 * free-space chain: allocation always fills the head page, so inserts alone
 * can never produce a chain longer than one and cannot show which bytes of
 * page+0x06 carry a real page number. */
static void cmd_delete(const char *path, DWORD key)
{
    static unsigned char data[DATA_SIZE];
    char posblk[POSBLK_SIZE];
    unsigned char keybuf[KEY_SIZE];
    DWORD dlen;
    int st;

    st = open_file(posblk, path);
    if (st != 0)
        die("open", st);

    memset(keybuf, 0, sizeof keybuf);
    keybuf[0] = (unsigned char)(key & 0xff);
    keybuf[1] = (unsigned char)((key >> 8) & 0xff);
    keybuf[2] = (unsigned char)((key >> 16) & 0xff);
    keybuf[3] = (unsigned char)((key >> 24) & 0xff);

    /* Btrieve deletes at the current position, so the record has to be got
     * first -- on the same open, or the position block means nothing. */
    dlen = DATA_SIZE;
    memset(data, 0, sizeof data);
    st = btrcall(B_GET_EQUAL, posblk, data, &dlen, keybuf, 4, 0);
    if (st != 0)
        die("get before delete", st);

    dlen = 0;
    st = btrcall(B_DELETE, posblk, NULL, &dlen, NULL, 0, 0);
    printf("delete key=%lu status=%d (%s)\n",
           (unsigned long)key, st, status_name(st));
    if (st != 0)
        die("delete", st);

    { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }
}

int main(int argc, char **argv)
{
    HMODULE dll;
    const char *cmd, *path;

    if (argc < 3) {
        fprintf(stderr,
            "usage: varfree <create|create_dup|insert|get|delete> <file.DAT> ...\n"
            "  create <path>\n"
            "  insert <path> <key> <total> <fillbyte>\n"
            "  get    <path> <key>\n");
        return 2;
    }
    cmd  = argv[1];
    path = argv[2];

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

    if (!strcmp(cmd, "create")) {
        cmd_create(path);
    } else if (!strcmp(cmd, "create_dup")) {
        cmd_create_dup(path);
    } else if (!strcmp(cmd, "insert")) {
        if (argc < 6) {
            fprintf(stderr, "FAIL: insert needs <key> <total> <fillbyte>\n");
            return 2;
        }
        cmd_insert(path, (DWORD)strtoul(argv[3], NULL, 10),
                   (WORD)atoi(argv[4]),
                   (unsigned char)strtoul(argv[5], NULL, 0));
    } else if (!strcmp(cmd, "get")) {
        if (argc < 4) { fprintf(stderr, "FAIL: get needs <key>\n"); return 2; }
        cmd_get(path, (DWORD)strtoul(argv[3], NULL, 10));
    } else if (!strcmp(cmd, "delete")) {
        if (argc < 4) { fprintf(stderr, "FAIL: delete needs <key>\n"); return 2; }
        cmd_delete(path, (DWORD)strtoul(argv[3], NULL, 10));
    } else {
        fprintf(stderr, "FAIL: unknown command %s\n", cmd);
        return 2;
    }

    { DWORD d = 0; char pb[POSBLK_SIZE] = {0}; btrcall(B_STOP, pb, NULL, &d, NULL, 0, 0); }
    return 0;
}
