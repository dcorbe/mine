/*
 * xactprobe -- THROWAWAY research probe, forked from updprobe.c.
 *
 * Answers docs/plans/2026-08-12-btrieve-finish.md Task 6's open questions
 * about Btrieve ops 19/20/21 (dfaBegTrans/dfaEndTrans/dfaAbtTrans) against
 * genuine Pervasive Btrieve 6.15 under Wine, since crates/mbbs has no
 * transaction support at all to reason from and the plan says to ask the
 * oracle rather than invent the semantics:
 *
 *   - nested begin: status, or silently accepted?
 *   - end without begin / abort without begin: what status?
 *   - are writes made inside a transaction visible to a GET on the same
 *     client before end?
 *   - does abort roll back inserts? updates? deletes?
 *   - does a failing op inside a transaction implicitly abort it?
 *   - does loktyp (WAITBV=0 vs NOWTBV=200) change anything for one client?
 *
 * Each subcommand is a full scenario run inside ONE process, because the
 * transaction is a property of the Btrieve *session* (DFAAPI.C's
 * dfaBegTrans passes a NULL posblk to btvu -- it is not scoped to one open
 * file), so it can only be observed by issuing several ops without
 * restarting the client. Where "does it persist" matters, the scenario
 * closes and reopens the file inside the same run, and prints again after
 * the whole process exits and a fresh invocation reopens the file, so a
 * commit/rollback that only looks real because the model is still cached in
 * this process cannot be mistaken for one that hit disk.
 *
 * Geometry: reclen 32, pagesize 512, one 4-byte unique unsigned-binary key
 * at record byte 1 (1-based) -- deliberately NOT variable-length, so the
 * transaction question is not entangled with the fragment-chain question
 * Task 4 already answered separately.
 *
 * Commands (each opens the path itself; state lives on disk and in the
 * Microkernel's own cache):
 *
 *   create          <path>
 *   nested          <path>
 *   end_no_begin    <path>
 *   abort_no_begin  <path>
 *   visibility      <path> <key>
 *   abort_insert    <path> <key>
 *   abort_update    <path> <key>
 *   abort_delete    <path> <key>
 *   fail_inside     <path> <key1> <key2>
 *   loktyp          <path>
 *   get             <path> <key>
 */
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>

#define B_OPEN        0
#define B_CLOSE       1
#define B_INSERT      2
#define B_UPDATE      3
#define B_DELETE      4
#define B_GET_EQUAL   5
#define B_CREATE     14
#define B_STAT       15
#define B_BEGIN_TRANS 19
#define B_END_TRANS   20
#define B_ABORT_TRANS 21
#define B_STOP        25

#define WAITBV 0
#define NOWTBV 200

#define POSBLK_SIZE 128
#define RECLEN 32
#define DATA_SIZE 256
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

static const char *status_name(int st)
{
    switch (st) {
    case 0:  return "OK";
    case 1:  return "invalid operation";
    case 2:  return "I/O error";
    case 3:  return "file not open";
    case 4:  return "key value not found";
    case 5:  return "duplicate key value";
    case 8:  return "invalid positioning";
    case 9:  return "end of file";
    case 11: return "invalid filename";
    case 12: return "file not found";
    case 18: return "disk full";
    case 20: return "not a Btrieve function / engine not active";
    case 22: return "data buffer too short";
    case 24: return "page size error";
    case 30: return "not a Btrieve file";
    case 46: return "access denied";
    case 54: return "variable page error";
    case 85: return "file locked by another process";
    default: return "?";
    }
}

static void die(const char *what, int st)
{
    fprintf(stderr, "FAIL %s: status %d (%s)\n", what, st, status_name(st));
    exit(1);
}

static void fill_record(unsigned char *record, DWORD key, unsigned char tag)
{
    unsigned i;
    record[0] = (unsigned char)(key & 0xff);
    record[1] = (unsigned char)((key >> 8) & 0xff);
    record[2] = (unsigned char)((key >> 16) & 0xff);
    record[3] = (unsigned char)((key >> 24) & 0xff);
    for (i = 4; i < RECLEN; i++)
        record[i] = tag;
}

static void keybuf_from(unsigned char *keybuf, DWORD key)
{
    memset(keybuf, 0, KEY_SIZE);
    keybuf[0] = (unsigned char)(key & 0xff);
    keybuf[1] = (unsigned char)((key >> 8) & 0xff);
    keybuf[2] = (unsigned char)((key >> 16) & 0xff);
    keybuf[3] = (unsigned char)((key >> 24) & 0xff);
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

    fs->reclen = RECLEN;
    fs->pagesize = 512;
    fs->indexes_raw = 1;
    fs->flags = 0;

    ks->position = 1;
    ks->length = 4;
    ks->flags = 0x0100; /* EXTTYPE only: unique, ascending */
    ks->ext_type = 0x0e; /* unsigned binary */

    st = btrcall(B_CREATE, posblk, data, &dlen, keybuf,
                (BYTE)(strlen(keybuf) + 1), (char)0);
    if (st != 0)
        die("create", st);
    printf("created %s reclen=%d pagesize=512 flags=0 (fixed)\n", path, RECLEN);
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

static int do_insert(char *posblk, DWORD key, unsigned char tag)
{
    unsigned char record[DATA_SIZE];
    unsigned char keybuf[KEY_SIZE];
    DWORD dlen;
    memset(record, 0, sizeof record);
    fill_record(record, key, tag);
    dlen = RECLEN;
    memset(keybuf, 0, sizeof keybuf);
    return btrcall(B_INSERT, posblk, record, &dlen, keybuf, sizeof keybuf - 1, 0);
}

static int do_update(char *posblk, DWORD key, unsigned char tag)
{
    unsigned char record[DATA_SIZE];
    unsigned char keybuf[KEY_SIZE];
    DWORD dlen;
    int st;

    keybuf_from(keybuf, key);
    dlen = DATA_SIZE;
    memset(record, 0, sizeof record);
    st = btrcall(B_GET_EQUAL, posblk, record, &dlen, keybuf, 4, 0);
    if (st != 0)
        return st;
    fill_record(record, key, tag);
    dlen = RECLEN;
    return btrcall(B_UPDATE, posblk, record, &dlen, keybuf, 4, 0);
}

static int do_delete(char *posblk, DWORD key)
{
    unsigned char record[DATA_SIZE];
    unsigned char keybuf[KEY_SIZE];
    DWORD dlen;
    int st;

    keybuf_from(keybuf, key);
    dlen = DATA_SIZE;
    memset(record, 0, sizeof record);
    st = btrcall(B_GET_EQUAL, posblk, record, &dlen, keybuf, 4, 0);
    if (st != 0)
        return st;
    dlen = 0;
    return btrcall(B_DELETE, posblk, NULL, &dlen, NULL, 0, 0);
}

/* GET_EQUAL, report status and (if found) the tag byte at record[4] so a
 * caller can tell an old value from a new one without a hex dump. */
static int do_get(char *posblk, DWORD key, unsigned char *tag_out)
{
    unsigned char record[DATA_SIZE];
    unsigned char keybuf[KEY_SIZE];
    DWORD dlen;
    int st;

    keybuf_from(keybuf, key);
    dlen = DATA_SIZE;
    memset(record, 0, sizeof record);
    st = btrcall(B_GET_EQUAL, posblk, record, &dlen, keybuf, 4, 0);
    if (st == 0 && tag_out)
        *tag_out = record[4];
    return st;
}

/* Mirrors btrvprobe.c's stat_file(): B_STAT wants a real (non-NULL) key
 * buffer to write into even though this only reads the file spec back --
 * an earlier version passed NULL/0 here and the engine page-faulted writing
 * through it (measured: "Unhandled page fault on write access to
 * 00000000"). keynum -1 asks for the file spec rather than one key's. */
static DWORD record_count(char *posblk)
{
    static unsigned char data[DATA_SIZE];
    DWORD dlen = DATA_SIZE;
    char keybuf[KEY_SIZE];
    FileSpec *fs = (FileSpec *)data;
    memset(data, 0, sizeof data);
    memset(keybuf, 0, sizeof keybuf);
    if (btrcall(B_STAT, posblk, data, &dlen, keybuf, sizeof keybuf - 1, (char)-1) != 0)
        return 0xFFFFFFFF;
    return fs->records;
}

static void cmd_nested(const char *path)
{
    char posblk[POSBLK_SIZE];
    int st;

    st = open_file(posblk, path);
    if (st != 0) die("open", st);

    st = btrcall(B_BEGIN_TRANS + WAITBV, posblk, NULL, &(DWORD){0}, NULL, 0, 0);
    printf("nested: outer begin status=%d (%s)\n", st, status_name(st));

    st = btrcall(B_BEGIN_TRANS + WAITBV, posblk, NULL, &(DWORD){0}, NULL, 0, 0);
    printf("nested: inner begin status=%d (%s)\n", st, status_name(st));

    st = btrcall(B_ABORT_TRANS, posblk, NULL, &(DWORD){0}, NULL, 0, 0);
    printf("nested: abort status=%d (%s)\n", st, status_name(st));

    /* One more abort: if the engine nests, this asks whether the OUTER
     * begin is still active (a second abort would succeed) or whether the
     * single abort above already ended it (this would then be an
     * abort-without-begin). */
    st = btrcall(B_ABORT_TRANS, posblk, NULL, &(DWORD){0}, NULL, 0, 0);
    printf("nested: second abort status=%d (%s)\n", st, status_name(st));

    { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }
}

static void cmd_end_no_begin(const char *path)
{
    char posblk[POSBLK_SIZE];
    int st;
    st = open_file(posblk, path);
    if (st != 0) die("open", st);
    st = btrcall(B_END_TRANS, posblk, NULL, &(DWORD){0}, NULL, 0, 0);
    printf("end_no_begin: status=%d (%s)\n", st, status_name(st));
    { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }
}

static void cmd_abort_no_begin(const char *path)
{
    char posblk[POSBLK_SIZE];
    int st;
    st = open_file(posblk, path);
    if (st != 0) die("open", st);
    st = btrcall(B_ABORT_TRANS, posblk, NULL, &(DWORD){0}, NULL, 0, 0);
    printf("abort_no_begin: status=%d (%s)\n", st, status_name(st));
    { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }
}

static void cmd_visibility(const char *path, DWORD key)
{
    char posblk[POSBLK_SIZE];
    int st;
    unsigned char tag;

    st = open_file(posblk, path);
    if (st != 0) die("open", st);

    st = btrcall(B_BEGIN_TRANS + WAITBV, posblk, NULL, &(DWORD){0}, NULL, 0, 0);
    printf("visibility: begin status=%d (%s)\n", st, status_name(st));

    st = do_insert(posblk, key, 0xAA);
    printf("visibility: insert status=%d (%s)\n", st, status_name(st));

    st = do_get(posblk, key, &tag);
    printf("visibility: get-inside-txn status=%d (%s) tag=%02x\n", st, status_name(st), tag);

    st = btrcall(B_END_TRANS, posblk, NULL, &(DWORD){0}, NULL, 0, 0);
    printf("visibility: end status=%d (%s)\n", st, status_name(st));

    { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }

    st = open_file(posblk, path);
    if (st != 0) die("reopen", st);
    st = do_get(posblk, key, &tag);
    printf("visibility: get-after-close-reopen status=%d (%s) tag=%02x\n", st, status_name(st), tag);
    { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }
}

static void cmd_abort_insert(const char *path, DWORD key)
{
    char posblk[POSBLK_SIZE];
    int st;
    unsigned char tag;

    st = open_file(posblk, path);
    if (st != 0) die("open", st);

    printf("abort_insert: count-before=%lu\n", (unsigned long)record_count(posblk));

    st = btrcall(B_BEGIN_TRANS + WAITBV, posblk, NULL, &(DWORD){0}, NULL, 0, 0);
    printf("abort_insert: begin status=%d (%s)\n", st, status_name(st));

    st = do_insert(posblk, key, 0xBB);
    printf("abort_insert: insert status=%d (%s)\n", st, status_name(st));

    st = do_get(posblk, key, &tag);
    printf("abort_insert: get-inside-txn status=%d (%s) tag=%02x\n", st, status_name(st), tag);

    st = btrcall(B_ABORT_TRANS, posblk, NULL, &(DWORD){0}, NULL, 0, 0);
    printf("abort_insert: abort status=%d (%s)\n", st, status_name(st));

    st = do_get(posblk, key, &tag);
    printf("abort_insert: get-after-abort-same-session status=%d (%s)\n", st, status_name(st));

    printf("abort_insert: count-after-same-session=%lu\n", (unsigned long)record_count(posblk));

    { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }

    st = open_file(posblk, path);
    if (st != 0) die("reopen", st);
    st = do_get(posblk, key, &tag);
    printf("abort_insert: get-after-close-reopen status=%d (%s)\n", st, status_name(st));
    printf("abort_insert: count-after-close-reopen=%lu\n", (unsigned long)record_count(posblk));
    { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }
}

static void cmd_abort_update(const char *path, DWORD key)
{
    char posblk[POSBLK_SIZE];
    int st;
    unsigned char tag;

    st = open_file(posblk, path);
    if (st != 0) die("open", st);

    /* Baseline, outside any transaction. */
    st = do_insert(posblk, key, 0x11);
    printf("abort_update: baseline insert status=%d (%s)\n", st, status_name(st));

    st = btrcall(B_BEGIN_TRANS + WAITBV, posblk, NULL, &(DWORD){0}, NULL, 0, 0);
    printf("abort_update: begin status=%d (%s)\n", st, status_name(st));

    st = do_update(posblk, key, 0x22);
    printf("abort_update: update status=%d (%s)\n", st, status_name(st));

    st = do_get(posblk, key, &tag);
    printf("abort_update: get-inside-txn status=%d (%s) tag=%02x (expect 22 if visible)\n", st, status_name(st), tag);

    st = btrcall(B_ABORT_TRANS, posblk, NULL, &(DWORD){0}, NULL, 0, 0);
    printf("abort_update: abort status=%d (%s)\n", st, status_name(st));

    st = do_get(posblk, key, &tag);
    printf("abort_update: get-after-abort-same-session status=%d (%s) tag=%02x (expect 11 if rolled back)\n", st, status_name(st), tag);

    { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }

    st = open_file(posblk, path);
    if (st != 0) die("reopen", st);
    st = do_get(posblk, key, &tag);
    printf("abort_update: get-after-close-reopen status=%d (%s) tag=%02x\n", st, status_name(st), tag);
    { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }
}

static void cmd_abort_delete(const char *path, DWORD key)
{
    char posblk[POSBLK_SIZE];
    int st;
    unsigned char tag;

    st = open_file(posblk, path);
    if (st != 0) die("open", st);

    st = do_insert(posblk, key, 0x33);
    printf("abort_delete: baseline insert status=%d (%s)\n", st, status_name(st));

    st = btrcall(B_BEGIN_TRANS + WAITBV, posblk, NULL, &(DWORD){0}, NULL, 0, 0);
    printf("abort_delete: begin status=%d (%s)\n", st, status_name(st));

    st = do_delete(posblk, key);
    printf("abort_delete: delete status=%d (%s)\n", st, status_name(st));

    st = do_get(posblk, key, &tag);
    printf("abort_delete: get-inside-txn status=%d (%s) (expect 4/not-found if visible)\n", st, status_name(st));

    st = btrcall(B_ABORT_TRANS, posblk, NULL, &(DWORD){0}, NULL, 0, 0);
    printf("abort_delete: abort status=%d (%s)\n", st, status_name(st));

    st = do_get(posblk, key, &tag);
    printf("abort_delete: get-after-abort-same-session status=%d (%s) tag=%02x (expect found+33 if rolled back)\n", st, status_name(st), tag);

    { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }

    st = open_file(posblk, path);
    if (st != 0) die("reopen", st);
    st = do_get(posblk, key, &tag);
    printf("abort_delete: get-after-close-reopen status=%d (%s) tag=%02x\n", st, status_name(st), tag);
    { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }
}

static void cmd_fail_inside(const char *path, DWORD key1, DWORD key2)
{
    char posblk[POSBLK_SIZE];
    int st;
    unsigned char tag;

    st = open_file(posblk, path);
    if (st != 0) die("open", st);

    st = btrcall(B_BEGIN_TRANS + WAITBV, posblk, NULL, &(DWORD){0}, NULL, 0, 0);
    printf("fail_inside: begin status=%d (%s)\n", st, status_name(st));

    st = do_insert(posblk, key1, 0x44);
    printf("fail_inside: first insert (key1) status=%d (%s)\n", st, status_name(st));

    st = do_insert(posblk, key1, 0x55);
    printf("fail_inside: duplicate insert (key1 again) status=%d (%s) (expect 5)\n", st, status_name(st));

    st = do_insert(posblk, key2, 0x66);
    printf("fail_inside: insert after failure (key2) status=%d (%s)\n", st, status_name(st));

    st = do_get(posblk, key1, &tag);
    printf("fail_inside: get key1 after failure, still-in-txn status=%d (%s)\n", st, status_name(st));
    st = do_get(posblk, key2, &tag);
    printf("fail_inside: get key2 after failure, still-in-txn status=%d (%s)\n", st, status_name(st));

    st = btrcall(B_END_TRANS, posblk, NULL, &(DWORD){0}, NULL, 0, 0);
    printf("fail_inside: end status=%d (%s)\n", st, status_name(st));

    { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }

    st = open_file(posblk, path);
    if (st != 0) die("reopen", st);
    st = do_get(posblk, key1, &tag);
    printf("fail_inside: get key1 after close/reopen status=%d (%s)\n", st, status_name(st));
    st = do_get(posblk, key2, &tag);
    printf("fail_inside: get key2 after close/reopen status=%d (%s)\n", st, status_name(st));
    { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }
}

static void cmd_loktyp(const char *path)
{
    char posblk[POSBLK_SIZE];
    int st;

    st = open_file(posblk, path);
    if (st != 0) die("open", st);

    st = btrcall(B_BEGIN_TRANS + WAITBV, posblk, NULL, &(DWORD){0}, NULL, 0, 0);
    printf("loktyp: begin(WAITBV=0) status=%d (%s)\n", st, status_name(st));
    st = btrcall(B_END_TRANS, posblk, NULL, &(DWORD){0}, NULL, 0, 0);
    printf("loktyp: end status=%d (%s)\n", st, status_name(st));

    st = btrcall(B_BEGIN_TRANS + NOWTBV, posblk, NULL, &(DWORD){0}, NULL, 0, 0);
    printf("loktyp: begin(NOWTBV=200) status=%d (%s)\n", st, status_name(st));
    st = btrcall(B_END_TRANS, posblk, NULL, &(DWORD){0}, NULL, 0, 0);
    printf("loktyp: end status=%d (%s)\n", st, status_name(st));

    { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }
}

static void cmd_get(const char *path, DWORD key)
{
    char posblk[POSBLK_SIZE];
    int st;
    unsigned char tag = 0;
    st = open_file(posblk, path);
    if (st != 0) die("open", st);
    st = do_get(posblk, key, &tag);
    printf("get: status=%d (%s) tag=%02x\n", st, status_name(st), tag);
    { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }
}

int main(int argc, char **argv)
{
    HMODULE dll;
    const char *cmd, *path;

    if (argc < 3) {
        fprintf(stderr, "usage: xactprobe <cmd> <file.DAT> ...\n");
        return 2;
    }
    cmd = argv[1];
    path = argv[2];

    dll = LoadLibraryA("WBTRV32.DLL");
    if (!dll) {
        fprintf(stderr, "FAIL: cannot load WBTRV32.DLL (error %lu)\n", (unsigned long)GetLastError());
        return 1;
    }
    btrcall = (BTRCALL_FN)GetProcAddress(dll, "BTRCALL");
    if (!btrcall) {
        fprintf(stderr, "FAIL: WBTRV32.DLL exports no BTRCALL\n");
        return 1;
    }

    if (!strcmp(cmd, "create")) {
        cmd_create(path);
    } else if (!strcmp(cmd, "nested")) {
        cmd_nested(path);
    } else if (!strcmp(cmd, "end_no_begin")) {
        cmd_end_no_begin(path);
    } else if (!strcmp(cmd, "abort_no_begin")) {
        cmd_abort_no_begin(path);
    } else if (!strcmp(cmd, "visibility")) {
        if (argc < 4) { fprintf(stderr, "needs <key>\n"); return 2; }
        cmd_visibility(path, (DWORD)strtoul(argv[3], NULL, 10));
    } else if (!strcmp(cmd, "abort_insert")) {
        if (argc < 4) { fprintf(stderr, "needs <key>\n"); return 2; }
        cmd_abort_insert(path, (DWORD)strtoul(argv[3], NULL, 10));
    } else if (!strcmp(cmd, "abort_update")) {
        if (argc < 4) { fprintf(stderr, "needs <key>\n"); return 2; }
        cmd_abort_update(path, (DWORD)strtoul(argv[3], NULL, 10));
    } else if (!strcmp(cmd, "abort_delete")) {
        if (argc < 4) { fprintf(stderr, "needs <key>\n"); return 2; }
        cmd_abort_delete(path, (DWORD)strtoul(argv[3], NULL, 10));
    } else if (!strcmp(cmd, "fail_inside")) {
        if (argc < 5) { fprintf(stderr, "needs <key1> <key2>\n"); return 2; }
        cmd_fail_inside(path, (DWORD)strtoul(argv[3], NULL, 10), (DWORD)strtoul(argv[4], NULL, 10));
    } else if (!strcmp(cmd, "loktyp")) {
        cmd_loktyp(path);
    } else if (!strcmp(cmd, "get")) {
        if (argc < 4) { fprintf(stderr, "needs <key>\n"); return 2; }
        cmd_get(path, (DWORD)strtoul(argv[3], NULL, 10));
    } else {
        fprintf(stderr, "FAIL: unknown command %s\n", cmd);
        return 2;
    }

    { DWORD d = 0; char pb[POSBLK_SIZE] = {0}; btrcall(B_STOP, pb, NULL, &d, NULL, 0, 0); }
    return 0;
}
