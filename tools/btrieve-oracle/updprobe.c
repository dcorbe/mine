/*
 * updprobe -- THROWAWAY research probe, forked from varprobe_multi.c.
 *
 * Answers docs/plans/2026-08-12-btrieve-finish.md Task 4's open question:
 * does a real Btrieve GET on a variable-length record return a `datalen`
 * shorter than the file's maximum when the record's actual content is
 * shorter, and does an UPDATE honour an offered length shorter than the
 * buffer -- or does it always report/commit the full declared length,
 * matching what crates/mbbs/src/shims/btrieve.rs's deliver() does today?
 *
 * Geometry matches WCCTEXT.DAT, measured directly off a copy with
 * `btrvprobe stat`: reclen 22, pagesize 2048, flags 0x0001 (variable),
 * one key (position 1, length 4 here rather than WCCTEXT's 18 -- this rig
 * only needs a unique lookup key, not the real field layout).
 *
 * Commands (each opens and closes the file itself; state lives on disk and
 * in the Microkernel's own cache, exactly as with varprobe_multi.c):
 *
 *   create   <path>
 *   insert   <path> <key> <total>
 *   get      <path> <key>
 *   update   <path> <key> <offer_total> <zero_last_n>
 */
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>

#define B_OPEN       0
#define B_CLOSE      1
#define B_INSERT     2
#define B_UPDATE     3
#define B_GET_EQUAL  5
#define B_CREATE    14
#define B_STOP      25

#define POSBLK_SIZE 128
#define DATA_SIZE 32768   /* must stay < 65536; engine reads only the low 16
                              bits of the length pointer -- see btrvprobe.c's
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

/* Create a WCCTEXT-shaped variable-length file: reclen 22, pagesize 2048,
 * flags 0x0001 (bit 0 -- variable-length records; crates/mbbs/src/btrieve.rs
 * mod flag::VARIABLE), one unique unsigned-binary key at record byte 1
 * (1-based), 4 bytes long. */
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
    fs->pagesize = 2048;
    fs->indexes_raw = 1;
    fs->flags = 0x0001;   /* variable-length records */

    ks->position = 1;
    ks->length = 4;
    ks->flags = 0x0100;   /* EXTTYPE only: unique, ascending */
    ks->ext_type = 0x0e;  /* unsigned binary, matches WCCTEXT key 0's type */

    st = btrcall(B_CREATE, posblk, data, &dlen, keybuf,
                (BYTE)(strlen(keybuf) + 1), (char)0);
    if (st != 0)
        die("create", st);
    printf("created %s reclen=22 pagesize=2048 flags=0x0001 (variable)\n", path);
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

/* Fill `record` (must be >= total bytes) with: key at [0..4), fixed filler
 * 0xEE at [4..22), and a nonzero, key-dependent, distinguishable pattern at
 * [22..total). Never produces a zero byte, so any zero found later is
 * provably not something this probe put there. */
static void fill_record(unsigned char *record, DWORD key, WORD total)
{
    unsigned i;
    record[0] = (unsigned char)(key & 0xff);
    record[1] = (unsigned char)((key >> 8) & 0xff);
    record[2] = (unsigned char)((key >> 16) & 0xff);
    record[3] = (unsigned char)((key >> 24) & 0xff);
    for (i = 4; i < 22 && i < total; i++)
        record[i] = 0xEE;
    for (i = 22; i < total; i++)
        record[i] = (unsigned char)(0x80 + ((key * 7 + i) % 64));
}

static void cmd_insert(const char *path, DWORD key, WORD total)
{
    char posblk[POSBLK_SIZE];
    unsigned char record[DATA_SIZE];
    unsigned char keybuf[KEY_SIZE];
    DWORD dlen;
    int st;

    st = open_file(posblk, path);
    if (st != 0)
        die("open", st);

    memset(record, 0, sizeof record);
    fill_record(record, key, total);

    dlen = total;
    memset(keybuf, 0, sizeof keybuf);
    st = btrcall(B_INSERT, posblk, record, &dlen, keybuf, sizeof keybuf - 1, 0);
    printf("insert key=%lu offered_total=%u status=%d (%s) insert_returned_dlen=%lu\n",
           (unsigned long)key, total, st, status_name(st), (unsigned long)dlen);

    { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }
}

static void keybuf_from(unsigned char *keybuf, DWORD key)
{
    memset(keybuf, 0, KEY_SIZE);
    keybuf[0] = (unsigned char)(key & 0xff);
    keybuf[1] = (unsigned char)((key >> 8) & 0xff);
    keybuf[2] = (unsigned char)((key >> 16) & 0xff);
    keybuf[3] = (unsigned char)((key >> 24) & 0xff);
}

/* GET_EQUAL the record for `key`, offering a DATA_SIZE buffer (far larger
 * than any WCCTEXT-shaped record could need), and report what the engine
 * wrote back as the datalen -- this IS Q1's measurement. */
static void cmd_get(const char *path, DWORD key)
{
    static unsigned char data[DATA_SIZE];
    char posblk[POSBLK_SIZE];
    unsigned char keybuf[KEY_SIZE];
    DWORD dlen;
    int st;
    unsigned i, trailing_zero;

    st = open_file(posblk, path);
    if (st != 0)
        die("open", st);

    keybuf_from(keybuf, key);
    dlen = DATA_SIZE;
    memset(data, 0, sizeof data);
    st = btrcall(B_GET_EQUAL, posblk, data, &dlen, keybuf, 4, 0);
    if (st != 0) {
        printf("get key=%lu: status=%d (%s)\n", (unsigned long)key, st, status_name(st));
        { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }
        return;
    }

    trailing_zero = 0;
    for (i = dlen; i > 0 && data[i - 1] == 0; i--)
        trailing_zero++;

    printf("get key=%lu: status=0 (OK) datalen=%lu trailing_zero_bytes=%u",
           (unsigned long)key, (unsigned long)dlen, trailing_zero);
    printf(" tail16=");
    for (i = (dlen >= 16 ? dlen - 16 : 0); i < dlen; i++)
        printf("%02x", data[i]);
    printf("\n");

    { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }
}

/*
 * GET_EQUAL the record for `key`, zero its last `zero_last_n` bytes (of the
 * length the GET actually returned), then UPDATE offering `offer_total` as
 * the length. Reports the GET's datalen, the UPDATE's status and returned
 * datalen. Run `get` again afterward to see what committed.
 */
static void cmd_update(const char *path, DWORD key, WORD offer_total, unsigned zero_last_n)
{
    static unsigned char data[DATA_SIZE];
    char posblk[POSBLK_SIZE];
    unsigned char keybuf[KEY_SIZE];
    DWORD dlen;
    int st;
    unsigned i;

    st = open_file(posblk, path);
    if (st != 0)
        die("open", st);

    keybuf_from(keybuf, key);
    dlen = DATA_SIZE;
    memset(data, 0, sizeof data);
    st = btrcall(B_GET_EQUAL, posblk, data, &dlen, keybuf, 4, 0);
    if (st != 0)
        die("get_equal (for update)", st);
    printf("update key=%lu: pre-get datalen=%lu\n", (unsigned long)key, (unsigned long)dlen);

    if (zero_last_n > dlen) {
        fprintf(stderr, "FAIL: zero_last_n %u exceeds datalen %lu\n",
                zero_last_n, (unsigned long)dlen);
        exit(1);
    }
    for (i = 0; i < zero_last_n; i++)
        data[dlen - 1 - i] = 0;

    dlen = offer_total;
    st = btrcall(B_UPDATE, posblk, data, &dlen, keybuf, 4, 0);
    printf("update key=%lu: offered=%u zeroed_last=%u status=%d (%s) update_returned_dlen=%lu\n",
           (unsigned long)key, offer_total, zero_last_n, st, status_name(st), (unsigned long)dlen);

    { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }
}

int main(int argc, char **argv)
{
    HMODULE dll;
    const char *cmd, *path;

    if (argc < 3) {
        fprintf(stderr,
            "usage: updprobe <create|insert|get|update> <file.DAT> ...\n"
            "  create <path>\n"
            "  insert <path> <key> <total>\n"
            "  get    <path> <key>\n"
            "  update <path> <key> <offer_total> <zero_last_n>\n");
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
    } else if (!strcmp(cmd, "insert")) {
        if (argc < 5) { fprintf(stderr, "FAIL: insert needs <key> <total>\n"); return 2; }
        cmd_insert(path, (DWORD)strtoul(argv[3], NULL, 10), (WORD)atoi(argv[4]));
    } else if (!strcmp(cmd, "get")) {
        if (argc < 4) { fprintf(stderr, "FAIL: get needs <key>\n"); return 2; }
        cmd_get(path, (DWORD)strtoul(argv[3], NULL, 10));
    } else if (!strcmp(cmd, "update")) {
        if (argc < 6) { fprintf(stderr, "FAIL: update needs <key> <offer_total> <zero_last_n>\n"); return 2; }
        cmd_update(path, (DWORD)strtoul(argv[3], NULL, 10), (WORD)atoi(argv[4]),
                   (unsigned)atoi(argv[5]));
    } else {
        fprintf(stderr, "FAIL: unknown command %s\n", cmd);
        return 2;
    }

    { DWORD d = 0; char pb[POSBLK_SIZE] = {0}; btrcall(B_STOP, pb, NULL, &d, NULL, 0, 0); }
    return 0;
}
