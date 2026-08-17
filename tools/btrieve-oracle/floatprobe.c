/*
 * floatprobe -- how does genuine Btrieve 6.15 order a FLOAT key (type 0x02)?
 *
 * `keys::Kind::of` has no ordering for type 0x02 and refuses the file, which
 * is the sole refusal in this repository's 471-file corpus:
 * `MULTIACS.DAT`, whose key 1 has an eight-byte float segment.
 *
 * # Why a rig of positive values would prove nothing
 *
 * A bytewise comparison of IEEE doubles gives the right answer for positives
 * and exactly the wrong one for negatives, because the sign bit is the high
 * bit and the remaining bits then count *upwards* as the magnitude grows.
 * Every value below is one that some wrong reading gets right:
 *
 *   -1.0, 1.0       sign handling at all
 *   -1e308, -1.0    ordering WITHIN the negatives, which is where a bytewise
 *                   compare inverts
 *   -0.0, 0.0       whether the two zeroes are one key or two
 *   4-byte width    whether 0x02 at four bytes is an f32
 *
 * # The rig
 *
 * Fixed-length records, reclen 16, pagesize 512, one key at record byte 1.
 * `create8` gives it eight bytes of type 0x02; `create4` gives it four. The
 * key permits duplicates so that -0.0 and 0.0 can both be inserted whatever
 * the engine thinks of them -- a unique key would answer status 5 and hide
 * the answer behind a refusal.
 *
 * Commands, one operation per process, each ending in B_STOP:
 *
 *   floatprobe create8 <path>
 *   floatprobe create4 <path>
 *   floatprobe insert  <path> <value>       e.g. -1.0, -1e308, nan, -0.0
 *   floatprobe walk    <path>               step the key in order
 *
 * **Never reuse a path across runs.** The Microkernel caches pages by path.
 */
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define B_OPEN       0
#define B_CLOSE      1
#define B_INSERT     2
#define B_GET_NEXT   6
#define B_GET_FIRST 12
#define B_CREATE    14
#define B_STOP      25

#define POSBLK_SIZE 128
#define DATA_SIZE 4096
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
    case 4:  return "key value not found";
    case 5:  return "duplicate key value";
    case 9:  return "end of file";
    case 12: return "file not found";
    case 24: return "page size error";
    case 29: return "invalid key length";
    case 30: return "not a Btrieve file";
    case 45: return "invalid key flags";
    default: return "?";
    }
}

static void die(const char *what, int st)
{
    fprintf(stderr, "FAIL %s: status %d (%s)\n", what, st, status_name(st));
    exit(1);
}

/* `width` is the key segment's length: 8 for a double, 4 for a float. */
static void create_typed(const char *path, WORD width, BYTE type)
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

    fs->reclen = 16;
    fs->pagesize = 512;
    fs->indexes_raw = 1;
    fs->flags = 0x0000;

    ks->position = 1;
    ks->length = width;
    ks->flags = 0x0101;   /* DUPLICATE | EXTTYPE -- see the header comment */
    ks->ext_type = type;

    st = btrcall(B_CREATE, posblk, data, &dlen, keybuf,
                 (BYTE)(strlen(keybuf) + 1), (char)0);
    if (st != 0)
        die("create", st);
    printf("created %s reclen=16 key=1 len=%u type=%#04x\n", path, width, type);
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

/* Record layout: the key at [0..width), then a four-byte tag at [8..12) so a
 * walk can name which insert each record came from without decoding the key
 * the engine is being asked about. */
static void cmd_insert(const char *path, WORD width, const char *text, DWORD tag)
{
    char posblk[POSBLK_SIZE];
    unsigned char record[DATA_SIZE];
    unsigned char keybuf[KEY_SIZE];
    DWORD dlen;
    int st;
    double d = strtod(text, NULL);
    float f = (float)d;

    st = open_file(posblk, path);
    if (st != 0)
        die("open", st);

    memset(record, 0, 16);
    if (width == 8)
        memcpy(record, &d, 8);
    else
        memcpy(record, &f, 4);
    memcpy(record + 8, &tag, 4);

    dlen = 16;
    memset(keybuf, 0, sizeof keybuf);
    st = btrcall(B_INSERT, posblk, record, &dlen, keybuf, sizeof keybuf - 1, 0);
    printf("insert %-10s tag=%lu bytes=", text, (unsigned long)tag);
    for (unsigned i = 0; i < width; i++)
        printf("%02x", record[i]);
    printf(" status=%d (%s)\n", st, status_name(st));

    { DWORD d2 = 0; btrcall(B_CLOSE, posblk, NULL, &d2, NULL, 0, 0); }
}

/* Insert a key given as raw hex, so a type whose encoding is not known can
 * still be ordered.
 *
 * `bfloat` (0x09) is Borland's, and is not IEEE: which byte holds the
 * exponent and where the sign bit sits are exactly what is in question, so
 * feeding it a C `double` would assume the answer. Feeding it chosen bit
 * patterns and reading back the order does not. */
static void cmd_insert_raw(const char *path, const char *hex, DWORD tag)
{
    char posblk[POSBLK_SIZE];
    unsigned char record[DATA_SIZE];
    unsigned char keybuf[KEY_SIZE];
    DWORD dlen;
    int st;
    size_t i, n = strlen(hex) / 2;

    st = open_file(posblk, path);
    if (st != 0)
        die("open", st);

    memset(record, 0, 16);
    for (i = 0; i < n && i < 8; i++) {
        char byte[3] = { hex[2 * i], hex[2 * i + 1], 0 };
        record[i] = (unsigned char)strtoul(byte, NULL, 16);
    }
    memcpy(record + 8, &tag, 4);

    dlen = 16;
    memset(keybuf, 0, sizeof keybuf);
    st = btrcall(B_INSERT, posblk, record, &dlen, keybuf, sizeof keybuf - 1, 0);
    printf("insert raw %-18s tag=%-3lu status=%d (%s)\n",
           hex, (unsigned long)tag, st, status_name(st));

    { DWORD d2 = 0; btrcall(B_CLOSE, posblk, NULL, &d2, NULL, 0, 0); }
}

/* Walk printing only the raw key bytes -- no interpretation at all. */
static void cmd_walk_raw(const char *path, WORD width)
{
    char posblk[POSBLK_SIZE];
    unsigned char data[DATA_SIZE];
    unsigned char keybuf[KEY_SIZE];
    DWORD dlen;
    int st, n = 0;

    st = open_file(posblk, path);
    if (st != 0)
        die("open", st);

    memset(keybuf, 0, sizeof keybuf);
    dlen = sizeof data;
    st = btrcall(B_GET_FIRST, posblk, data, &dlen, keybuf, KEY_SIZE - 1, 0);
    while (st == 0) {
        DWORD tag;
        unsigned i;
        memcpy(&tag, data + 8, 4);
        printf("  %2d: tag=%-3lu key=", n, (unsigned long)tag);
        for (i = 0; i < width; i++)
            printf("%02x", data[i]);
        printf("\n");
        n++;
        dlen = sizeof data;
        st = btrcall(B_GET_NEXT, posblk, data, &dlen, keybuf, KEY_SIZE - 1, 0);
    }
    printf("walked %d, ended status=%d (%s)\n", n, st, status_name(st));

    { DWORD d2 = 0; btrcall(B_CLOSE, posblk, NULL, &d2, NULL, 0, 0); }
}

/* Step the key from lowest to highest and print what the engine considers
 * that order to be. THIS is the measurement. */
static void cmd_walk(const char *path, WORD width)
{
    char posblk[POSBLK_SIZE];
    unsigned char data[DATA_SIZE];
    unsigned char keybuf[KEY_SIZE];
    DWORD dlen;
    int st, n = 0;

    st = open_file(posblk, path);
    if (st != 0)
        die("open", st);

    memset(keybuf, 0, sizeof keybuf);
    dlen = sizeof data;
    st = btrcall(B_GET_FIRST, posblk, data, &dlen, keybuf, KEY_SIZE - 1, 0);
    while (st == 0) {
        DWORD tag;
        double d = 0;
        float f = 0;
        memcpy(&tag, data + 8, 4);
        if (width == 8) { memcpy(&d, data, 8); }
        else            { memcpy(&f, data, 4); d = f; }
        printf("  %2d: tag=%-3lu value=%-14g bytes=", n, (unsigned long)tag, d);
        for (unsigned i = 0; i < width; i++)
            printf("%02x", data[i]);
        printf("\n");
        n++;
        dlen = sizeof data;
        st = btrcall(B_GET_NEXT, posblk, data, &dlen, keybuf, KEY_SIZE - 1, 0);
    }
    printf("walked %d, ended status=%d (%s)\n", n, st, status_name(st));

    { DWORD d2 = 0; btrcall(B_CLOSE, posblk, NULL, &d2, NULL, 0, 0); }
}

int main(int argc, char **argv)
{
    HMODULE dll;
    const char *cmd, *path;

    if (argc < 3) {
        fprintf(stderr,
            "usage: floatprobe <create8|create4|insert8|insert4|walk8|walk4> <file.DAT> ...\n");
        return 2;
    }
    cmd  = argv[1];
    path = argv[2];

    dll = LoadLibraryA("WBTRV32.DLL");
    if (!dll) {
        fprintf(stderr, "FAIL: cannot load WBTRV32.DLL (%lu)\n",
                (unsigned long)GetLastError());
        return 1;
    }
    btrcall = (BTRCALL_FN)GetProcAddress(dll, "BTRCALL");
    if (!btrcall) {
        fprintf(stderr, "FAIL: WBTRV32.DLL exports no BTRCALL\n");
        return 1;
    }

    if (!strcmp(cmd, "create8"))      create_typed(path, 8, 0x02);
    else if (!strcmp(cmd, "create4")) create_typed(path, 4, 0x02);
    else if (!strcmp(cmd, "insert8")) {
        if (argc < 5) { fprintf(stderr, "FAIL: insert needs <value> <tag>\n"); return 2; }
        cmd_insert(path, 8, argv[3], (DWORD)strtoul(argv[4], NULL, 10));
    } else if (!strcmp(cmd, "insert4")) {
        if (argc < 5) { fprintf(stderr, "FAIL: insert needs <value> <tag>\n"); return 2; }
        cmd_insert(path, 4, argv[3], (DWORD)strtoul(argv[4], NULL, 10));
    } else if (!strcmp(cmd, "insertraw")) {
        if (argc < 5) { fprintf(stderr, "FAIL: insertraw needs <hex> <tag>\n"); return 2; }
        cmd_insert_raw(path, argv[3], (DWORD)strtoul(argv[4], NULL, 10));
    } else if (!strcmp(cmd, "walkraw")) {
        if (argc < 4) { fprintf(stderr, "FAIL: walkraw needs <width>\n"); return 2; }
        cmd_walk_raw(path, (WORD)atoi(argv[3]));
    } else if (!strcmp(cmd, "createt")) {
        /* Any extended type at any width, so that "will the engine even make
         * this key" is a measurement rather than an assumption. */
        if (argc < 5) {
            fprintf(stderr, "FAIL: createt needs <width> <type>\n");
            return 2;
        }
        create_typed(path, (WORD)atoi(argv[3]), (BYTE)strtoul(argv[4], NULL, 0));
    } else if (!strcmp(cmd, "walk8"))  cmd_walk(path, 8);
    else if (!strcmp(cmd, "walk4"))    cmd_walk(path, 4);
    else { fprintf(stderr, "FAIL: unknown command %s\n", cmd); return 2; }

    { DWORD d = 0; char pb[POSBLK_SIZE] = {0}; btrcall(B_STOP, pb, NULL, &d, NULL, 0, 0); }
    return 0;
}
