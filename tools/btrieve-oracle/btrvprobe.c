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
/* winsock2.h must come before windows.h: it defines _WINSOCKAPI_, which stops
 * windows.h pulling in the old winsock.h behind it. */
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Btrieve operation codes, Btrieve Programmer's Reference (1998). */
#define B_OPEN       0
#define B_CLOSE      1
#define B_INSERT     2
#define B_GET_EQUAL  5
#define B_GET_NEXT   6
#define B_GET_FIRST 12
#define B_CREATE    14
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

/* Key flag bit 6: this key is ordered from the largest value down. `cmd_walk`
 * flags a step that goes the wrong way as an ORDER REGRESSION, and without
 * this it flagged every step of a descending key -- so it could not validate
 * one at all, and reported WALK MISMATCH on a walk that was exactly right.
 * `WCCUSERS` key 2 is MajorMUD's experience field, descending and permitting
 * duplicates, which is the key this program most needs to be able to check.
 *
 * The count it produced was itself evidence of what it was measuring: a forged
 * file of 150 records over 54 distinct values reported 53 regressions -- one
 * per strictly-decreasing step, none for the steps within a duplicate group,
 * because equal keys compare equal in either direction. */
#define KFLG_DESCENDING 0x0040

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

/*
 * Create a file with one duplicate-permitting, descending, 4-byte key.
 *
 * B_CREATE takes the filename in the KEY buffer, exactly as B_OPEN does (see
 * open_file() above), and the file specification in the DATA buffer: one
 * FileSpec followed by one KeySpec per key segment -- the same layout B_STAT
 * *returns*, so this reuses those structs rather than declaring new ones
 * (Task 6 of docs/plans/2026-08-08-fsd-oracle-implementation.md).
 *
 * The shape hardcoded here is not general-purpose; it is WCCUSERS key 2 minus
 * everything this rig does not need. WCCUSERS key 2 is experience: 4 bytes at
 * record offset 60 (position 61, 1-based), descending, duplicates permitted --
 * every newly created MajorMUD character has exp 0, so every save collides on
 * it. This file drops the other 59+ fields WCCUSERS carries and keeps only
 * that key, at position 1 of a 12-byte record, so a duplicate-chain index can
 * be measured without a whole character record to build around.
 */
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

    fs->reclen = 12;      /* 4-byte key + an 8-byte tag; see cmd_insert() */
    fs->pagesize = 512;   /* smallest legal page; nothing here needs more */
    /* One key. Not the 0x4001-shaped value fs_indexes() has to mask out of a
     * STAT reply -- that flag bit is something the engine sets when it
     * REPORTS a file, not something a caller sets when it SPECIFIES one. */
    fs->indexes_raw = 1;

    ks->position = 1;               /* 1-based; struct comment above open_file() */
    ks->length = 4;
    /* Bit 0 (0x01) = duplicates permitted, bit 6 (0x40) = descending, bit 8
     * (0x0100) = EXTTYPE. Without EXTTYPE the engine ignores ext_type below
     * and creates a classic type-0 (string) key instead -- measured: a first
     * version left it unset, and the resulting file's STAT reply read back
     * type=0 despite ext_type having been sent as 14. Confirmed against a
     * working B_CREATE caller, not guessed: DUP/MODIFIABLE/BIN/NUL/SEGMENT/
     * SEQ/DEC/SUP/EXTTYPE are `docs/mirrors/github-syntax53-Nightmare-Redux/
     * modBtrieve.bas:34-49`, and `modUpdateFile.bas:717,721` sets
     * `KeyFlags = EXTTYPE` with `ExtDataType = 15` on a real create call
     * whose FileSpec/KeySpec field layout (`modFieldmaps.bas:710-728`) lines
     * up byte-for-byte with the struct here. */
    ks->flags = 0x0141;
    ks->ext_type = KT_UNSIGNED_BINARY;   /* 14; matches WCCUSERS key 2's type */

    /* Key-number argument 0 means "fail if the file already exists" rather
     * than -1's "overwrite". The Microkernel caches pages by path and outlives
     * its clients (see the file header comment); if a stale file is sitting
     * under this name, that must surface as an error, not a silent reuse of
     * whatever the cache remembers. */
    st = btrcall(B_CREATE, posblk, data, &dlen, keybuf,
                (BYTE)(strlen(keybuf) + 1), (char)0);
    if (st != ST_OK)
        die("create", st);

    { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }
}

/*
 * Insert `count` records whose key values collide in groups of three.
 *
 * A unique-keyed insert can never exercise the duplicate-chain code this rig
 * exists to measure, so `value = index / 3` makes records 0,1,2 share key 0,
 * 3,4,5 share key 1, and so on -- 30 records land on 10 distinct key values.
 * Bytes 4..12 of the 12-byte record carry the ordinal (not part of the key)
 * so `dump` can tell the three records in a group apart.
 */
static void cmd_insert(const char *path, int count)
{
    char posblk[POSBLK_SIZE];
    unsigned char record[12];
    unsigned char keybuf[KEY_SIZE];
    DWORD dlen;
    int i, st;
    unsigned failures = 0;

    st = open_file(posblk, path, MODE_NORMAL);
    if (st != ST_OK)
        die("open", st);

    for (i = 0; i < count; i++) {
        DWORD value = (DWORD)(i / 3);

        record[0] = (unsigned char)(value & 0xff);
        record[1] = (unsigned char)((value >> 8) & 0xff);
        record[2] = (unsigned char)((value >> 16) & 0xff);
        record[3] = (unsigned char)((value >> 24) & 0xff);
        memset(record + 4, 0, 8);
        record[4] = (unsigned char)(i & 0xff);
        record[5] = (unsigned char)((i >> 8) & 0xff);

        /* B_INSERT derives the key value from the record itself at the
         * position the file spec declared; the key buffer here is an OUTPUT
         * -- the engine writes back the key it extracted -- not an input, so
         * it starts zeroed rather than pre-filled. */
        dlen = sizeof record;
        memset(keybuf, 0, sizeof keybuf);
        st = btrcall(B_INSERT, posblk, record, &dlen, keybuf,
                    sizeof keybuf - 1, (char)0);
        printf("insert %3d key %lu: status %d (%s)\n",
               i, (unsigned long)value, st, status_name(st));
        if (st != ST_OK)
            failures++;
    }

    { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }

    if (failures) {
        fprintf(stderr, "FAIL: %u of %d inserts did not return OK\n", failures, count);
        exit(1);
    }
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
    int st, have_prev = 0, descending = 0;

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
        descending = (keys[first].flags & KFLG_DESCENDING) != 0;
    }

    dlen = DATA_SIZE;
    memset(keybuf, 0, sizeof keybuf);
    st = btrcall(B_GET_FIRST, posblk, data, &dlen, keybuf,
                 sizeof keybuf - 1, (char)keynum);

    while (st == ST_OK) {
        count++;
        if (have_prev && klen
            && (descending ? key_cmp(prev, keybuf, klen, coll) < 0
                           : key_cmp(prev, keybuf, klen, coll) > 0)) {
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
    printf("key         %d (len %u, %u segment(s), type %u, %s%s)\n", keynum, klen,
           segments, keys[first].ext_type, collation_name(coll),
           descending ? ", descending" : "");
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
 * permutation of the middle preserves the extremes. Diffing two of these is
 * what closes that: the shipped file against the same file reindexed by this
 * host, with the real engine reading both. `compare.sh` drives it.
 *
 * This is the KEYS; `dump` below is the RECORDS. Two questions, two commands:
 * an index can name the right records in the wrong order, and a reader can
 * reassemble the wrong bytes for records the index names correctly.
 */
static void cmd_keys(const char *path, int keynum)
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

    /* Both counts, so a caller can tell a coherent reading from an incoherent
     * one. It is not hypothetical: the Microkernel caches pages by path and
     * outlives its clients, and presenting two different files under one name
     * made it yield 2,861 keys out of a file whose own stat, on this same
     * open, said 1,950. See the note in sweep.sh. */
    fprintf(stderr, "dumped %lu keys of %lu\n", count, (unsigned long)fs.records);

    { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }
}

/*
 * Print every record the engine yields, in key order, as hex.
 *
 * WHY: `walk` and `descend` check the engine's KEYS against ours. Neither
 * looks at a single byte of a record's data, which is exactly what
 * variable-length reassembly gets wrong -- a reader that followed the fragment
 * chain to the wrong page, or kept the four-byte next-pointer prefix as
 * payload, would pass both while handing the module the wrong text.
 *
 * The engine returns the FULL reassembled record here: `dlen` comes back as
 * the length Btrieve actually produced, 2022 for WCCTEXT (22 of fixed record
 * and 2000 of fragment), not the 22 a naive reader stops at. That makes this a
 * byte-exact oracle for crates/mbbs/src/btrieve/variable.rs.
 *
 * The output is one line per record: the ordinal, the length the engine
 * reported, and the bytes. Deliberately dumb and diffable -- 3467 records of
 * 2022 bytes is 14 MB of hex, which is nothing, and any encoding cleverness
 * here would be a second place for a bug to hide.
 */
static void cmd_dump(const char *path, int keynum)
{
    static unsigned char data[DATA_SIZE];
    char posblk[POSBLK_SIZE];
    unsigned char keybuf[KEY_SIZE];
    FileSpec fs;
    KeySpec keys[24];
    DWORD dlen;
    unsigned long count = 0, i;
    int st;

    st = open_file(posblk, path, MODE_READ_ONLY);
    if (st != ST_OK)
        die("open", st);
    st = stat_file(posblk, &fs, keys, 24);
    if (st != ST_OK)
        die("stat", st);

    dlen = DATA_SIZE;
    memset(keybuf, 0, sizeof keybuf);
    st = btrcall(B_GET_FIRST, posblk, data, &dlen, keybuf,
                 sizeof keybuf - 1, (char)keynum);

    while (st == ST_OK) {
        printf("%lu %lu ", count, (unsigned long)dlen);
        for (i = 0; i < dlen; i++)
            printf("%02x", data[i]);
        printf("\n");
        count++;

        dlen = DATA_SIZE;
        st = btrcall(B_GET_NEXT, posblk, data, &dlen, keybuf,
                     sizeof keybuf - 1, (char)keynum);
    }

    /* Same trap `descend` fell into: a run that died partway would otherwise
     * print a plausible prefix and exit 0. */
    if (st != ST_END_OF_FILE) {
        fprintf(stderr, "dumped %lu (stopped early)\n", count);
        die("get_next", st);
    }
    fprintf(stderr, "dumped      %lu\n", count);
    fprintf(stderr, "stat says   %lu\n", (unsigned long)fs.records);
    fprintf(stderr, "%s\n", count == fs.records ? "DUMP OK" : "DUMP MISMATCH");
    if (count != fs.records)
        exit(1);

    { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }
}

/*
 * serve: turn one TCP connection's framed requests into BTRCALLs, one at a
 * time, for crates/btrieve-engine's Rust client. Wire format is
 * docs/plans/2026-08-09-btrieve-engine-in-the-loop.md, Task 1:
 *
 *   Request   u32 frame_len | u16 op | [128] posblk | u32 datalen_in
 *                           | u32 databuf_len | databuf
 *                           | u8 keylen | i8 keynum | u32 keybuf_len | keybuf
 *   Response  u32 frame_len | i16 status | [128] posblk | u32 datalen_out
 *                           | u32 databuf_len | databuf
 *                           | u32 keybuf_len | keybuf
 *
 * frame_len counts everything after itself. Every integer is little-endian,
 * and so is this machine (x86 under Wine), so encoding is a plain memcpy --
 * no htons/ntohs anywhere in this function.
 *
 * Stateless by design: posblk is 128 bytes of engine-private cursor state
 * that a real Btrieve client owns and passes back in on the next call. Both
 * directions carry it on the wire so the caller -- not this process -- holds
 * cursor state, the way the genuine host does.
 */
#define OP_QUIT 0xFFFF
/* Not a real Btrieve status (those are small non-negative numbers, see
 * status_name() above): a distinct out-of-band value for "refused", so a
 * caller can never mistake a protocol refusal for the engine's own answer. */
#define SERVE_STATUS_REQUEST_TOO_LARGE (-1)

static DWORD get_u32(const unsigned char *p)
{
    return (DWORD)p[0] | ((DWORD)p[1] << 8) | ((DWORD)p[2] << 16) | ((DWORD)p[3] << 24);
}

static void put_u32(unsigned char *p, DWORD v)
{
    p[0] = (unsigned char)v;
    p[1] = (unsigned char)(v >> 8);
    p[2] = (unsigned char)(v >> 16);
    p[3] = (unsigned char)(v >> 24);
}

static void put_u16(unsigned char *p, WORD v)
{
    p[0] = (unsigned char)v;
    p[1] = (unsigned char)(v >> 8);
}

/* Reads exactly `len` bytes. Returns 1 on success, 0 if the peer closed
 * before any byte of this read arrived (a clean point to stop at). A close
 * mid-read is not clean -- the other side wrote a frame_len it never
 * finished -- so that exits loudly instead of returning a short frame. */
static int recv_all(SOCKET s, void *buf, int len)
{
    char *p = (char *)buf;
    int got = 0;
    while (got < len) {
        int n = recv(s, p + got, len - got, 0);
        if (n == SOCKET_ERROR) {
            fprintf(stderr, "FAIL: serve: recv failed: %d\n", WSAGetLastError());
            exit(1);
        }
        if (n == 0) {
            if (got == 0)
                return 0;
            fprintf(stderr, "FAIL: serve: connection closed mid-frame\n");
            exit(1);
        }
        got += n;
    }
    return 1;
}

static void send_all(SOCKET s, const void *buf, int len)
{
    const char *p = (const char *)buf;
    int sent = 0;
    while (sent < len) {
        int n = send(s, p + sent, len - sent, 0);
        if (n == SOCKET_ERROR) {
            fprintf(stderr, "FAIL: serve: send failed: %d\n", WSAGetLastError());
            exit(1);
        }
        sent += n;
    }
}

/* Handles one request already sitting in `body` (the frame_len prefix
 * already stripped) and sends the reply. `databuf` scratch is the caller's,
 * fixed at DATA_SIZE -- never a pointer to anything the wire sized for us,
 * so a request cannot make the engine write past it on a read call. */
static void serve_one(SOCKET client, const unsigned char *body, DWORD body_len,
                      unsigned char *databuf)
{
    unsigned pos = 0;
    WORD op;
    char posblk[POSBLK_SIZE];
    DWORD datalen_in, databuf_len_in, keybuf_len_in;
    BYTE keylen;
    char keynum;
    unsigned char keybuf[KEY_SIZE];
    unsigned char resp[2 + POSBLK_SIZE + 4 + 4 + DATA_SIZE + 4 + KEY_SIZE];
    unsigned rpos;
    DWORD dlen;
    int st;

    (void)body_len; /* the fixed layout below accounts for every byte read */

    op = (WORD)(body[pos] | (body[pos + 1] << 8));
    pos += 2;
    memcpy(posblk, body + pos, POSBLK_SIZE);
    pos += POSBLK_SIZE;
    datalen_in = get_u32(body + pos);
    pos += 4;
    databuf_len_in = get_u32(body + pos);
    pos += 4;

    if (datalen_in > DATA_SIZE || databuf_len_in > DATA_SIZE) {
        /* Refuse rather than silently truncate -- the ABI note at the top of
         * this file measured what a truncated length does: every B_STAT
         * comes back status 22 while the caller believes it asked for more. */
        rpos = 0;
        put_u16(resp + rpos, (WORD)SERVE_STATUS_REQUEST_TOO_LARGE);
        rpos += 2;
        memcpy(resp + rpos, posblk, POSBLK_SIZE);
        rpos += POSBLK_SIZE;
        put_u32(resp + rpos, 0);
        rpos += 4;
        put_u32(resp + rpos, 0);
        rpos += 4;
        put_u32(resp + rpos, 0);
        rpos += 4;
        {
            unsigned char frame[4];
            put_u32(frame, rpos);
            send_all(client, frame, 4);
            send_all(client, resp, rpos);
        }
        return;
    }

    memcpy(databuf, body + pos, databuf_len_in);
    pos += databuf_len_in;
    keylen = body[pos];
    pos += 1;
    keynum = (char)body[pos];
    pos += 1;
    keybuf_len_in = get_u32(body + pos);
    pos += 4;
    memset(keybuf, 0, sizeof keybuf);
    memcpy(keybuf, body + pos, keybuf_len_in < sizeof keybuf ? keybuf_len_in : sizeof keybuf);
    pos += keybuf_len_in;

    dlen = datalen_in;
    st = btrcall(op, posblk, databuf, &dlen, keybuf, keylen, keynum);

    rpos = 0;
    put_u16(resp + rpos, (WORD)(short)st);
    rpos += 2;
    memcpy(resp + rpos, posblk, POSBLK_SIZE);
    rpos += POSBLK_SIZE;
    put_u32(resp + rpos, dlen);
    rpos += 4;
    put_u32(resp + rpos, dlen);
    rpos += 4;
    memcpy(resp + rpos, databuf, dlen);
    rpos += dlen;
    put_u32(resp + rpos, keylen);
    rpos += 4;
    memcpy(resp + rpos, keybuf, keylen);
    rpos += keylen;

    {
        unsigned char frame[4];
        put_u32(frame, rpos);
        send_all(client, frame, 4);
        send_all(client, resp, rpos);
    }
}

static void cmd_serve(const char *port_str)
{
    WSADATA wsa;
    SOCKET listener, client;
    struct sockaddr_in addr;
    unsigned short port;
    static unsigned char databuf[DATA_SIZE];

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "FAIL: WSAStartup failed\n");
        exit(1);
    }

    listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCKET) {
        fprintf(stderr, "FAIL: socket() failed: %d\n", WSAGetLastError());
        exit(1);
    }

    port = (unsigned short)atoi(port_str);
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    /* Never 0.0.0.0: this exposes a database engine with no authentication
     * of any kind. */
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons(port);

    if (bind(listener, (struct sockaddr *)&addr, sizeof addr) == SOCKET_ERROR) {
        fprintf(stderr, "FAIL: bind() failed: %d\n", WSAGetLastError());
        exit(1);
    }
    if (listen(listener, 1) == SOCKET_ERROR) {
        fprintf(stderr, "FAIL: listen() failed: %d\n", WSAGetLastError());
        exit(1);
    }

    /* The Rust side waits on this line rather than sleeping. Under Wine
     * stdout is a pipe and therefore block-buffered, so the flush is not
     * optional. */
    printf("listening %u\n", port);
    fflush(stdout);

    client = accept(listener, NULL, NULL);
    if (client == INVALID_SOCKET) {
        fprintf(stderr, "FAIL: accept() failed: %d\n", WSAGetLastError());
        exit(1);
    }
    closesocket(listener);

    for (;;) {
        unsigned char len_bytes[4];
        DWORD frame_len;
        unsigned char *body;

        if (!recv_all(client, len_bytes, 4))
            break; /* peer closed cleanly between frames */

        frame_len = get_u32(len_bytes);
        body = malloc(frame_len);
        if (!body) {
            fprintf(stderr, "FAIL: serve: out of memory for a %lu-byte frame\n",
                    (unsigned long)frame_len);
            exit(1);
        }
        if (!recv_all(client, body, (int)frame_len)) {
            fprintf(stderr, "FAIL: serve: connection closed mid-frame\n");
            exit(1);
        }

        if (frame_len >= 2 && (WORD)(body[0] | (body[1] << 8)) == OP_QUIT) {
            free(body);
            break;
        }

        serve_one(client, body, frame_len, databuf);
        free(body);
    }

    closesocket(client);
    WSACleanup();

    /* main()'s own B_STOP-before-exit, below, covers this command too --
     * every command shares that one call rather than each sending its own. */
}

int main(int argc, char **argv)
{
    HMODULE dll;
    const char *cmd, *path;
    int keynum = 0;

    if (argc < 3) {
        fprintf(stderr,
            "usage: btrvprobe <stat|walk|descend|keys|dump|create|insert|serve> <file.VIR>|<port> [keynum|count]\n"
            "  stat     print the engine's own view of the file and its indexes\n"
            "  walk     GET_FIRST/GET_NEXT the whole file, check key order\n"
            "  descend  GET_EQUAL every key -- forces root-to-leaf traversal\n"
            "  keys     print every KEY in index order, for diffing two files\n"
            "  dump     print every record's BYTES, in key order, as hex\n"
            "  create   create a 12-byte-record file with one duplicate,\n"
            "           descending, 4-byte key (WCCUSERS key 2, minus the rest)\n"
            "  insert   insert <count> records; key values collide in groups of 3\n"
            "  serve    <port>: turn one TCP connection's framed requests into\n"
            "           BTRCALLs, for crates/btrieve-engine's Rust client\n");
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
    else if (!strcmp(cmd, "keys"))
        cmd_keys(path, keynum);
    else if (!strcmp(cmd, "dump"))
        cmd_dump(path, keynum);
    else if (!strcmp(cmd, "create"))
        cmd_create(path);
    else if (!strcmp(cmd, "insert")) {
        if (argc < 4) {
            fprintf(stderr, "FAIL: insert needs a record count\n");
            return 2;
        }
        cmd_insert(path, keynum);   /* argv[3], already parsed as `keynum` above */
    }
    else if (!strcmp(cmd, "serve"))
        cmd_serve(path);   /* `path` holds the port number for this command */
    else {
        fprintf(stderr, "FAIL: unknown command %s\n", cmd);
        return 2;
    }

    /* Tell the engine to release the client. Without this the Microkernel can
     * keep the file handle live past process exit under Wine. */
    { DWORD d = 0; char pb[POSBLK_SIZE] = {0}; btrcall(B_STOP, pb, NULL, &d, NULL, 0, 0); }
    return 0;
}
