/*
 * btrvprobe -- drive the genuine Pervasive Btrieve 6.15 engine against a file.
 *
 * WHY THIS EXISTS
 *
 * crates/mbbs/src/btrieve writes B-tree index pages. Nothing had ever read one
 * of those trees except the crate itself. The two oracles previously available
 * are both disqualified for the same reason: MBBSEmu's C# reader and its
 * wbtrv32 SQLite replacement BOTH page-walk the data pages and derive key order
 * by sorting records -- neither descends an index. A builder and a reader that
 * are wrong the same way agree with each other.
 *
 * This program calls the real thing: WBTRV32.DLL -> W32MKDE.EXE, the Btrieve
 * Technologies Microkernel Database Engine v6.15, under Wine. `descend` forces
 * a root-to-leaf tree traversal for every key in the file, which is the one
 * check no reimplementation on hand can perform.
 *
 * ABI NOTE
 *
 * The fourth parameter is a POINTER to the data length, in/out. MBBSEmu's
 * wbtrv32/wbtrv32.h declares it as a by-value DWORD, which does not match the
 * real DLL; the declaration used here follows a caller known to work against
 * genuine Btrieve, docs/mirrors/github-syntax53-Nightmare-Redux/modBtrieve.bas
 * line 88, where VB6's default ByRef makes `DL As Long` a DWORD*.
 *
 * The pointer is 32 bits wide but the engine only reads the LOW 16 BITS of the
 * length. Measured, not assumed: a first version passed DATA_SIZE == 65536 and
 * every B_STAT came back status 22, "data buffer too short" -- 65536 truncates
 * to a low word of zero. Hence DATA_SIZE below is capped under 64K, which is
 * also the largest record Btrieve 6.x can hold, so nothing is lost.
 *
 * BUILD  (see build.sh)
 *   i686-w64-mingw32-gcc -O2 -o btrvprobe.exe btrvprobe.c
 * The DLL is resolved at run time by name, so no import library is needed and
 * the engine can be swapped for a different build without relinking.
 */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Btrieve operation codes, Btrieve Programmer's Reference (1998). */
#define B_OPEN       0
#define B_CLOSE      1
#define B_GET_EQUAL  5
#define B_GET_NEXT   6
#define B_GET_FIRST 12
#define B_STAT      15
#define B_STOP      25

/* Open modes, passed in the key-number slot of B_OPEN. */
#define MODE_NORMAL     0
#define MODE_READ_ONLY (-2)

/* Status codes we act on by name; everything else is reported numerically. */
#define ST_OK              0
#define ST_END_OF_FILE     9

#define POSBLK_SIZE  128
#define DATA_SIZE   32768   /* must stay < 65536; see the ABI note above */
#define KEY_SIZE      256

typedef int (__stdcall *BTRCALL_FN)(WORD op, void *posblk, void *databuf,
                                    DWORD *datalen, void *keybuf,
                                    BYTE keylen, char keynum);

static BTRCALL_FN btrcall;

/* Btrieve's B_STAT reply: one file spec, then one key spec per index. */
#pragma pack(push, 1)
typedef struct {
    WORD  reclen;
    WORD  pagesize;
    /* Only the low byte is the key count. Measured against WCCSPELS.VIR, a
     * one-key file, where this WORD reads 0x4001: the count is 1 and 0x4000 is
     * a flag bit the Programmer's Reference does not put in this field. Every
     * other field of this struct verified correct on the same call (reclen
     * 253, pagesize 512, records 1379), so the layout is right and the extra
     * bits are real. Use fs_indexes() rather than reading this directly. */
    WORD  indexes_raw;
    DWORD records;
    WORD  flags;
    BYTE  dup_pointers;
    BYTE  unused;
    WORD  allocations;
} FileSpec;

typedef struct {
    WORD  position;      /* 1-based byte offset of the key within the record */
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

/* The key count, masked out of the raw field. See the FileSpec comment. */
static unsigned fs_indexes(const FileSpec *fs)
{
    return fs->indexes_raw & 0x00FF;
}

/* Key flag bit 4: this spec is one segment of a key that continues into the
 * next spec. Btrieve's stat reply carries one KeySpec PER SEGMENT, but the
 * count in the file spec is per KEY -- measured on WCCBANKS.VIR, which reports
 * `indexes 1` and one spec with this bit set, and is one key of two segments
 * (a 30-byte name and a 4-byte integer). So key N is NOT spec[N] once any
 * earlier key has more than one segment, and its length is not spec[N].length
 * either. This is the same distinction `crates/mbbs/src/btrieve/keys.rs` draws
 * between a key's `number` and its `definition`.
 *
 * A first version of this program indexed spec[N] directly. Nothing caught it,
 * because every MajorMUD file with a segmented key holds zero records -- so it
 * would have gone wrong for the first file this host ever wrote records into.
 */
#define KFLG_SEGMENTED 0x0010

/* Where key `keynum` starts in the spec array, and how long it is in total.
 * Returns 0 if the file has no such key. */
static int key_extent(const KeySpec *specs, unsigned specs_len, unsigned keys,
                      unsigned keynum, unsigned *first, unsigned *length,
                      unsigned *segments)
{
    unsigned i = 0, k;

    for (k = 0; k < keys; k++) {
        unsigned start = i, len = 0, n = 0;
        do {
            if (i >= specs_len)
                return 0;
            len += specs[i].length;
            n++;
        } while (specs[i++].flags & KFLG_SEGMENTED);
        if (k == keynum) {
            *first = start;
            *length = len;
            *segments = n;
            return 1;
        }
    }
    return 0;
}

static const char *status_name(int st)
{
    switch (st) {
    case 0:  return "OK";
    case 2:  return "I/O error";
    case 3:  return "file not open";
    case 4:  return "key value not found";
    case 5:  return "duplicate key value";
    case 6:  return "invalid key number";
    case 7:  return "different key number";
    case 8:  return "invalid positioning";
    case 9:  return "end of file";
    case 11: return "invalid filename";
    case 12: return "file not found";
    case 14: return "pre-image open/write error";
    case 18: return "disk full";
    case 20: return "record manager inactive";
    case 22: return "data buffer too short";
    case 24: return "page size error";
    case 30: return "not a Btrieve file";
    case 46: return "access denied";
    case 54: return "variable page error";
    case 58: return "compression buffer too short";
    case 62: return "incorrect descriptor";
    default: return "?";
    }
}

static void die(const char *what, int st)
{
    fprintf(stderr, "FAIL %s: status %d (%s)\n", what, st, status_name(st));
    exit(1);
}

/*
 * Btrieve extended key data types, from the enum MBBSEmu recovered at
 * MBBSEmu/Btrieve/Enums/EnumKeyDataType.cs. Only the collation class matters
 * here, not the semantics.
 */
#define KT_STRING          0x00
#define KT_INTEGER         0x01   /* signed, little-endian */
#define KT_LSTRING         0x0A
#define KT_ZSTRING         0x0B
#define KT_UNSIGNED        0x0D
#define KT_UNSIGNED_BINARY 0x0E
#define KT_AUTOINC         0x0F
#define KT_OLD_ASCII       0x20
#define KT_OLD_BINARY      0x21

/* How a key of this type sorts. Anything not listed is UNKNOWN on purpose:
 * reporting "not checked" is honest, where guessing memcmp would manufacture
 * false order violations. */
enum collation { COLL_UNKNOWN, COLL_BYTES, COLL_LE_UNSIGNED, COLL_LE_SIGNED };

static enum collation collation_of(unsigned type, unsigned len)
{
    switch (type) {
    case KT_STRING: case KT_LSTRING: case KT_ZSTRING: case KT_OLD_ASCII:
        return COLL_BYTES;
    case KT_INTEGER:
        return (len == 2 || len == 4) ? COLL_LE_SIGNED : COLL_UNKNOWN;
    case KT_UNSIGNED: case KT_UNSIGNED_BINARY: case KT_AUTOINC: case KT_OLD_BINARY:
        return (len == 2 || len == 4) ? COLL_LE_UNSIGNED : COLL_UNKNOWN;
    default:
        return COLL_UNKNOWN;
    }
}

static const char *collation_name(enum collation c)
{
    switch (c) {
    case COLL_BYTES:       return "bytewise";
    case COLL_LE_UNSIGNED: return "little-endian unsigned";
    case COLL_LE_SIGNED:   return "little-endian signed";
    default:               return "unknown -- order not checked";
    }
}

static unsigned long le_value(const unsigned char *k, unsigned len)
{
    return len == 2 ? (unsigned long)(k[0] | (k[1] << 8))
                    : (unsigned long)(k[0] | (k[1] << 8)
                                    | ((DWORD)k[2] << 16) | ((DWORD)k[3] << 24));
}

/*
 * Compare two key values the way the index orders them. Integer keys are
 * stored little-endian, so memcmp is WRONG for them -- a first version used it
 * and reported five phantom order violations on WCCSPELS, every one of them a
 * clean 0x00ff -> 0x0100 rollover (255 -> 256), which is ascending.
 */
static int key_cmp(const unsigned char *a, const unsigned char *b,
                   unsigned len, enum collation c)
{
    switch (c) {
    case COLL_LE_UNSIGNED: {
        unsigned long x = le_value(a, len), y = le_value(b, len);
        return x < y ? -1 : x > y ? 1 : 0;
    }
    case COLL_LE_SIGNED: {
        long x = len == 2 ? (long)(short)le_value(a, len) : (long)(int)le_value(a, len);
        long y = len == 2 ? (long)(short)le_value(b, len) : (long)(int)le_value(b, len);
        return x < y ? -1 : x > y ? 1 : 0;
    }
    case COLL_BYTES:
        return memcmp(a, b, len);
    default:
        return 0;   /* never flags a violation */
    }
}

/* Render a key value as hex, plus a decimal reading when it is a 2- or 4-byte
 * integer -- MajorMUD's keys are overwhelmingly u16/u32 record ids. */
static void print_key(const unsigned char *k, unsigned len)
{
    unsigned i;
    for (i = 0; i < len; i++)
        printf("%02x", k[i]);
    if (len == 2)
        printf(" (%u)", (unsigned)(k[0] | (k[1] << 8)));
    else if (len == 4)
        printf(" (%lu)", (unsigned long)(k[0] | (k[1] << 8)
                                       | ((DWORD)k[2] << 16) | ((DWORD)k[3] << 24)));
}

static int open_file(char *posblk, const char *path, int mode)
{
    DWORD dlen = 0;
    char keybuf[KEY_SIZE];

    memset(posblk, 0, POSBLK_SIZE);
    memset(keybuf, 0, sizeof keybuf);
    /* B_OPEN takes the filename in the KEY buffer, not the data buffer. */
    strncpy(keybuf, path, sizeof keybuf - 1);

    return btrcall(B_OPEN, posblk, NULL, &dlen, keybuf,
                   (BYTE)(strlen(keybuf) + 1), (char)mode);
}

static int stat_file(char *posblk, FileSpec *fs, KeySpec *keys, unsigned max_keys)
{
    static unsigned char data[DATA_SIZE];
    DWORD dlen = DATA_SIZE;
    char keybuf[KEY_SIZE];
    unsigned i, n;
    int st;

    memset(keybuf, 0, sizeof keybuf);
    st = btrcall(B_STAT, posblk, data, &dlen, keybuf, sizeof keybuf - 1, (char)-1);
    if (st != ST_OK)
        return st;

    memcpy(fs, data, sizeof *fs);
    /* Every spec that fits, not one per key: a segmented key occupies more than
     * one, and `key_extent` needs to see them all to add up its length. The
     * reply is bounded by DATA_SIZE and `max_keys` is the caller's array. */
    n = max_keys;
    if (sizeof(FileSpec) + n * sizeof(KeySpec) > DATA_SIZE)
        n = (DATA_SIZE - sizeof(FileSpec)) / sizeof(KeySpec);
    for (i = 0; i < n; i++)
        memcpy(&keys[i], data + sizeof(FileSpec) + i * sizeof(KeySpec), sizeof(KeySpec));
    return ST_OK;
}

static void cmd_stat(const char *path)
{
    char posblk[POSBLK_SIZE];
    FileSpec fs;
    KeySpec keys[24];
    unsigned i;
    int st;

    st = open_file(posblk, path, MODE_READ_ONLY);
    if (st != ST_OK)
        die("open", st);

    st = stat_file(posblk, &fs, keys, 24);
    if (st != ST_OK)
        die("stat", st);

    printf("file        %s\n", path);
    printf("reclen      %u\n", fs.reclen);
    printf("pagesize    %u\n", fs.pagesize);
    printf("indexes     %u (raw 0x%04x)\n", fs_indexes(&fs), fs.indexes_raw);
    printf("records     %lu\n", (unsigned long)fs.records);
    printf("flags       0x%04x\n", fs.flags);
    printf("allocations %u\n", fs.allocations);
    for (i = 0; i < fs_indexes(&fs) && i < 24; i++) {
        unsigned first, length, segments;
        if (!key_extent(keys, 24, fs_indexes(&fs), i, &first, &length, &segments))
            break;
        printf("key %u       pos=%u len=%u flags=0x%04x approx=%lu type=%u segments=%u\n",
               i, keys[first].position, length, keys[first].flags,
               (unsigned long)keys[first].approx_count, keys[first].ext_type, segments);
    }

    { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }
}

/* Walk the whole file in key order via GET_FIRST/GET_NEXT and check the key
 * sequence is non-decreasing. Reports the count the engine actually yields. */
static void cmd_walk(const char *path, int keynum)
{
    static unsigned char data[DATA_SIZE];
    char posblk[POSBLK_SIZE];
    unsigned char keybuf[KEY_SIZE], prev[KEY_SIZE];
    FileSpec fs;
    KeySpec keys[24];
    DWORD dlen;
    unsigned long count = 0, regressions = 0;
    unsigned klen, first, length = 0, segments = 0;
    enum collation coll;
    int st, have_prev = 0;

    st = open_file(posblk, path, MODE_READ_ONLY);
    if (st != ST_OK)
        die("open", st);
    st = stat_file(posblk, &fs, keys, 24);
    if (st != ST_OK)
        die("stat", st);
    klen = 0;
    coll = COLL_UNKNOWN;
    first = 0;
    if (keynum >= 0 && key_extent(keys, 24, fs_indexes(&fs), (unsigned)keynum,
                                  &first, &length, &segments)) {
        klen = length;
        /* A segmented key's collation is per segment; this program only knows
         * how to order a single one, and reports "not checked" rather than
         * manufacturing violations out of a whole-blob compare. */
        coll = segments == 1 ? collation_of(keys[first].ext_type, klen) : COLL_UNKNOWN;
    }

    dlen = DATA_SIZE;
    memset(keybuf, 0, sizeof keybuf);
    st = btrcall(B_GET_FIRST, posblk, data, &dlen, keybuf,
                 sizeof keybuf - 1, (char)keynum);

    while (st == ST_OK) {
        count++;
        if (have_prev && klen && key_cmp(prev, keybuf, klen, coll) > 0) {
            regressions++;
            if (regressions <= 5) {
                printf("  ORDER REGRESSION at record %lu: ", count);
                print_key(prev, klen);
                printf(" -> ");
                print_key(keybuf, klen);
                printf("\n");
            }
        }
        if (count == 1) {
            printf("first key   ");
            print_key(keybuf, klen);
            printf("\n");
        }
        memcpy(prev, keybuf, klen ? klen : 1);
        have_prev = 1;

        dlen = DATA_SIZE;
        st = btrcall(B_GET_NEXT, posblk, data, &dlen, keybuf,
                     sizeof keybuf - 1, (char)keynum);
    }

    if (st != ST_END_OF_FILE) {
        printf("walked      %lu (stopped early)\n", count);
        die("get_next", st);
    }
    if (have_prev) {
        printf("last key    ");
        print_key(prev, klen);
        printf("\n");
    }
    printf("key         %d (len %u, %u segment(s), type %u, %s)\n", keynum, klen,
           segments, keys[first].ext_type, collation_name(coll));
    printf("walked      %lu\n", count);
    printf("stat says   %lu\n", (unsigned long)fs.records);
    printf("regressions %lu%s\n", regressions,
           coll == COLL_UNKNOWN ? " (order not checked)" : "");
    printf("%s\n", (regressions == 0 && count == fs.records) ? "WALK OK" : "WALK MISMATCH");

    { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }
}

/*
 * The check that matters: for every key value in the file, ask the engine to
 * GET_EQUAL it. GET_EQUAL cannot be answered by scanning -- it descends from
 * the index root through interior pages to a leaf. A tree whose interior nodes
 * are malformed fails here even when a sequential walk succeeds, because a walk
 * can be served from the leaf level alone.
 */
static void cmd_descend(const char *path, int keynum)
{
    static unsigned char data[DATA_SIZE];
    static unsigned char *keyvals;
    char posblk[POSBLK_SIZE];
    unsigned char keybuf[KEY_SIZE];
    FileSpec fs;
    KeySpec keys[24];
    DWORD dlen;
    unsigned long count = 0, i, misses = 0, wrong_record = 0;
    unsigned klen, koff, first, segments;
    int st, collect_status, checkable;

    st = open_file(posblk, path, MODE_READ_ONLY);
    if (st != ST_OK)
        die("open", st);
    st = stat_file(posblk, &fs, keys, 24);
    if (st != ST_OK)
        die("stat", st);
    if (keynum < 0 || !key_extent(keys, 24, fs_indexes(&fs), (unsigned)keynum,
                                  &first, &klen, &segments)) {
        fprintf(stderr, "FAIL: key %d out of range, file has %u\n", keynum, fs_indexes(&fs));
        exit(1);
    }

    /*
     * GET_EQUAL succeeding only proves the engine reached SOME leaf entry
     * carrying the key. It does not prove the entry names the right record: an
     * index whose entries hold the correct key values but the wrong record
     * positions descends perfectly and hands back the wrong row, and a builder
     * that paired keys with positions incorrectly is exactly the bug this
     * program exists to catch. So the record itself is checked -- the key field
     * of what came back must equal what was asked for.
     *
     * `position` is the key's 1-based byte offset within the record. It is only
     * usable when the key is a single segment: a segmented key's bytes are not
     * contiguous in the record, so the check is declined rather than performed
     * wrongly. No MajorMUD file that holds records has a segmented key.
     */
    koff = keys[first].position ? keys[first].position - 1 : 0;
    checkable = keys[first].position != 0 && segments == 1;

    keyvals = malloc((size_t)fs.records * klen + klen);
    if (!keyvals) {
        fprintf(stderr, "FAIL: out of memory for %lu keys\n", (unsigned long)fs.records);
        exit(1);
    }

    /* Pass 1: collect every key value in order. */
    dlen = DATA_SIZE;
    st = btrcall(B_GET_FIRST, posblk, data, &dlen, keybuf,
                 sizeof keybuf - 1, (char)keynum);
    while (st == ST_OK && count < fs.records) {
        memcpy(keyvals + count * klen, keybuf, klen);
        count++;
        dlen = DATA_SIZE;
        st = btrcall(B_GET_NEXT, posblk, data, &dlen, keybuf,
                     sizeof keybuf - 1, (char)keynum);
    }
    /* A damaged tree makes the collection pass die partway with a real error,
     * and every key it did collect then descends cleanly -- so "0 failures"
     * would be reported for a file that is plainly broken. Caught by the
     * mutation test in docs/plans/2026-08-08-btrieve-real-oracle.md, which
     * scrambles index page 1 of WCCSPELS and got exactly that false pass. */
    collect_status = st;

    /* Pass 2: make the engine find each one by descending the tree. */
    for (i = 0; i < count; i++) {
        memcpy(keybuf, keyvals + i * klen, klen);
        dlen = DATA_SIZE;
        st = btrcall(B_GET_EQUAL, posblk, data, &dlen, keybuf,
                     (BYTE)klen, (char)keynum);
        if (st != ST_OK) {
            misses++;
            if (misses <= 5) {
                printf("  DESCENT FAILED for key ");
                print_key(keyvals + i * klen, klen);
                printf(": status %d (%s)\n", st, status_name(st));
            }
            continue;
        }
        if (checkable && dlen >= koff + klen
            && memcmp(data + koff, keyvals + i * klen, klen) != 0) {
            wrong_record++;
            if (wrong_record <= 5) {
                printf("  WRONG RECORD for key ");
                print_key(keyvals + i * klen, klen);
                printf(": record carries ");
                print_key(data + koff, klen);
                printf("\n");
            }
        }
    }

    printf("key         %d (len %u, at byte %u)\n", keynum, klen, koff);
    printf("collected   %lu\n", count);
    printf("stat says   %lu\n", (unsigned long)fs.records);
    printf("collect end %d (%s)\n", collect_status, status_name(collect_status));
    printf("descents    %lu\n", count);
    printf("failures    %lu\n", misses);
    printf("wrong rec   %lu%s\n", wrong_record,
           checkable ? "" : " (segmented key -- record not checked)");
    printf("%s\n", (misses == 0 && wrong_record == 0 && count == fs.records
                     && collect_status == ST_END_OF_FILE)
                    ? "DESCEND OK" : "DESCEND MISMATCH");

    free(keyvals);
    { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }
}

/*
 * Print every key in the index's order, one hex value per line.
 *
 * `walk` reports only the first and last key, so two files can agree on both
 * endpoints and on the record count while disagreeing about everything in
 * between -- which is exactly what a wrong key comparator produces, since a
 * permutation of the middle preserves the extremes. Diffing two dumps is what
 * closes that: the shipped file against the same file reindexed by this host,
 * with the real engine reading both.
 */
static void cmd_dump(const char *path, int keynum)
{
    static unsigned char data[DATA_SIZE];
    char posblk[POSBLK_SIZE];
    unsigned char keybuf[KEY_SIZE];
    FileSpec fs;
    KeySpec keys[24];
    DWORD dlen;
    unsigned long count = 0;
    unsigned klen, first, segments, i;
    int st;

    st = open_file(posblk, path, MODE_READ_ONLY);
    if (st != ST_OK)
        die("open", st);
    st = stat_file(posblk, &fs, keys, 24);
    if (st != ST_OK)
        die("stat", st);
    if (keynum < 0 || !key_extent(keys, 24, fs_indexes(&fs), (unsigned)keynum,
                                  &first, &klen, &segments)) {
        fprintf(stderr, "FAIL: key %d out of range, file has %u\n", keynum, fs_indexes(&fs));
        exit(1);
    }

    dlen = DATA_SIZE;
    memset(keybuf, 0, sizeof keybuf);
    st = btrcall(B_GET_FIRST, posblk, data, &dlen, keybuf,
                 sizeof keybuf - 1, (char)keynum);
    while (st == ST_OK) {
        for (i = 0; i < klen; i++)
            printf("%02x", keybuf[i]);
        printf("\n");
        count++;
        dlen = DATA_SIZE;
        st = btrcall(B_GET_NEXT, posblk, data, &dlen, keybuf,
                     sizeof keybuf - 1, (char)keynum);
    }
    if (st != ST_END_OF_FILE)
        die("get_next", st);
    fprintf(stderr, "dumped %lu keys of %lu\n", count, (unsigned long)fs.records);

    { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }
}

int main(int argc, char **argv)
{
    HMODULE dll;
    const char *cmd, *path;
    int keynum = 0;

    if (argc < 3) {
        fprintf(stderr,
            "usage: btrvprobe <stat|walk|descend|dump> <file.VIR> [keynum]\n"
            "  stat     print the engine's own view of the file and its indexes\n"
            "  walk     GET_FIRST/GET_NEXT the whole file, check key order\n"
            "  descend  GET_EQUAL every key -- forces root-to-leaf traversal\n"
            "  dump     print every key in index order, for diffing two files\n");
        return 2;
    }
    cmd  = argv[1];
    path = argv[2];
    if (argc > 3)
        keynum = atoi(argv[3]);

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

    if (!strcmp(cmd, "stat"))
        cmd_stat(path);
    else if (!strcmp(cmd, "walk"))
        cmd_walk(path, keynum);
    else if (!strcmp(cmd, "descend"))
        cmd_descend(path, keynum);
    else if (!strcmp(cmd, "dump"))
        cmd_dump(path, keynum);
    else {
        fprintf(stderr, "FAIL: unknown command %s\n", cmd);
        return 2;
    }

    /* Tell the engine to release the client. Without this the Microkernel can
     * keep the file handle live past process exit under Wine. */
    { DWORD d = 0; char pb[POSBLK_SIZE] = {0}; btrcall(B_STOP, pb, NULL, &d, NULL, 0, 0); }
    return 0;
}
