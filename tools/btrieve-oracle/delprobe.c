/*
 * delprobe -- THROWAWAY research probe, forked from xactprobe.c/updprobe.c.
 *
 * Answers the open questions for `Block::delete` (Btrieve op 4) against
 * genuine Pervasive Btrieve 6.15 under Wine, since crates/mbbs has no delete
 * on-disk implementation to reason from and the rule here is to ask the
 * oracle rather than invent the semantics:
 *
 *   - what happens to the deleted slot's bytes on disk (free-list link,
 *     zeroed, or left as garbage)?
 *   - what does the file control record's free-list head (fcr::FREE, 0x10)
 *     and record count (fcr::RECORDS_HIGH/LOW, 0x1a/0x1c) do?
 *   - what happens to the file's position/cursor after a delete -- can a
 *     GET_NEXT still work, and from where?
 *   - what status does a delete give with no established position, or a
 *     second delete right after the first with no reposition in between?
 *   - does a later insert reuse the freed slot (same file offset back)?
 *   - what happens on a variable-length file -- are fragment pages touched?
 *
 * Geometry: reclen 32, pagesize 2048, one 4-byte unique unsigned-binary key at
 * record byte 1 (1-based) -- same key/record shape as xactprobe.c's
 * fixed-length rig, but pagesize 2048 rather than 512.
 *
 * Pagesize 512 was tried first and produces a file with TWO consecutive
 * 512-byte chunks that both decode as plausible file control records (magic
 * "FC", same `pages` field) -- one reporting the pre-insert record count, one
 * reporting the post-insert count. Switching to pagesize 2048 did not remove
 * this -- **every page this live engine writes to a freshly `B_CREATE`d file
 * comes in a physical PAIR**, the FCR pair at pages 0/1, an index pair at
 * pages 2/3, a data-page pair elsewhere, each member of a pair carrying the
 * same encoded page NUMBER (`pages::Header::decode`'s `number`) but a
 * different `stamp` (the low 15 bits `pages.rs` already documents as
 * "preserved rather than interpreted" -- this is why), and the CURRENT
 * generation is whichever member of a pair has the higher stamp. Confirmed
 * this is not particular to this probe's own `create`: `btrvprobe.c`'s
 * `create`+`insert` -- the tool this whole plan's earlier oracle work has
 * been built on -- shows the identical pairing on a freshly built file
 * (`BTVCREATE.DAT`, `docs/delete-oracle-answer.md` has the raw page dump).
 *
 * None of the eighteen SHIPPED MajorMUD files show this: `WCCCLASS.DAT`
 * (copied straight from `tmp/`) has exactly one FCR at page 0 and nothing
 * pair-shaped after it. So shadow-pairing is a live-write, crash-recovery
 * artifact of a file this session's own client created and is still holding
 * open across writes, not a property of a file this host ever has to read or
 * write in production -- `Block::insert`/`Block::update` already write a
 * single, unpaired copy of every page they touch and that has already been
 * validated against real Btrieve reads. Consequence for THIS probe: reading
 * raw bytes from a `delprobe.exe create`d fixture needs a "pick the
 * higher-stamp page" resolution step the shipped files never need, so the
 * delete scenarios that need to inspect exact on-disk bytes run against a
 * copy of a real shipped file (`WCCCLASS.DAT`, 15 fixed 153-byte records, one
 * 2-byte autoincrement key) instead -- see `cmd_wcclass_delete` below --
 * while the scenarios that only need Btrieve API-level status codes (which
 * do not care about physical page shape) keep using this rig's own
 * `create`/`insert`.
 *
 * Commands (each opens its own file; state lives on disk and in the
 * Microkernel's own cache -- see sweep.sh's "path is never reused" note):
 *
 *   create              <path>
 *   create_mod          <path>
 *   create_var          <path>
 *   insert              <path> <key> <tag>
 *   insert_var          <path> <key> <total>
 *   get                 <path> <key>
 *   position            <path> <key>
 *   update              <path> <key> <newtag>
 *   update_key          <path> <oldkey> <newkey>
 *   delete              <path> <key>
 *   delete_only         <path> <key>
 *   delete_var          <path> <key>
 *   delete_no_position  <path>
 *   delete_twice        <path> <key>
 *   delete_missing_key  <path> <key>
 *   getnext_after_delete <path> <key1> <key2>
 *   reuse               <path> <key1> <key2>
 *   wcclass_delete      <path> <key16>
 *   raw                 <path> <offset> <len>
 */
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>

#define B_OPEN          0
#define B_CLOSE         1
#define B_INSERT        2
#define B_UPDATE        3
#define B_DELETE        4
#define B_GET_EQUAL     5
#define B_GET_NEXT      6
#define B_GET_FIRST    12
#define B_CREATE       14
#define B_STAT         15
#define B_GET_POSITION 22
#define B_STOP         25

#define POSBLK_SIZE 128
#define RECLEN       32
#define DATA_SIZE   256
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
    fs->pagesize = 2048;
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
    printf("created %s reclen=%d pagesize=2048 flags=0 (fixed)\n", path, RECLEN);
    { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }
}

/* Same rig as cmd_create, except the key is MODIFIABLE (attribute bit 1).
 *
 * cmd_create's key is not, and genuine 6.15 answers status 10 ("key value not
 * modifiable") to any update that changes it -- which makes the whole
 * "what does an update do to the index" question unmeasurable on that file.
 * It is not a hypothetical distinction: of the twelve v6 files The Rose ships,
 * RCI_HEL1 declares all six of its keys modifiable, and RCI_PLAY, RCI_NAM1,
 * RCI_RAND, RCI_SPEL and RCI_UNIV declare theirs too. */
static void cmd_create_mod(const char *path)
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
    fs->pagesize = 2048;
    fs->indexes_raw = 1;
    fs->flags = 0;

    ks->position = 1;
    ks->length = 4;
    ks->flags = 0x0102; /* EXTTYPE | MODIFIABLE: unique, ascending */
    ks->ext_type = 0x0e; /* unsigned binary */

    st = btrcall(B_CREATE, posblk, data, &dlen, keybuf,
                (BYTE)(strlen(keybuf) + 1), (char)0);
    if (st != 0)
        die("create_mod", st);
    printf("created %s reclen=%d pagesize=2048 key flags=0x0102 (modifiable)\n",
           path, RECLEN);
    { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }
}

/* Variable-length rig, matching updprobe.c's create (WCCTEXT-shaped): reclen
 * 22, pagesize 2048, flags 0x0001, one unique 4-byte unsigned-binary key at
 * record byte 1. Only used to see what a delete does to a fragment pointer;
 * Block::delete refuses variable-length files regardless of the answer, the
 * same way Block::update already does. */
static void cmd_create_var(const char *path)
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
    fs->flags = 0x0001;

    ks->position = 1;
    ks->length = 4;
    ks->flags = 0x0100;
    ks->ext_type = 0x0e;

    st = btrcall(B_CREATE, posblk, data, &dlen, keybuf,
                (BYTE)(strlen(keybuf) + 1), (char)0);
    if (st != 0)
        die("create_var", st);
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

/* B_GET_POSITION (op 22) was tried here and dropped: a call to it, or to
 * B_DELETE shortly after one, page-faulted inside WBTRV32.DLL and left a
 * `winedbg --auto` process hanging on stdin, wedging the shared Microkernel
 * server for every other probe until killed by hand
 * (`docs/delete-oracle-answer.md` has the transcript). Whether the crash's
 * true cause was this call specifically, or the shared engine having already
 * been left corrupted by an earlier mistake in this same session (reusing a
 * file's path after recreating it at a different pagesize -- the exact hazard
 * `sweep.sh` already warns about) was not disentangled; it was cheaper to
 * stop calling an op this delete investigation does not need than to keep
 * chasing it. `Block::delete`'s own `position` parameter is this host's
 * internal file-offset convention regardless -- not whatever op 22 returns --
 * so nothing downstream depends on this working.
 *
 * Reuse detection instead reads the free-list head from the FCR before and
 * after (see `cmd_reuse` and `docs/delete-oracle-answer.md`'s Q5). */

static int do_delete(char *posblk)
{
    DWORD dlen = 0;
    return btrcall(B_DELETE, posblk, NULL, &dlen, NULL, 0, 0);
}

static void cmd_insert(const char *path, DWORD key, unsigned tag)
{
    char posblk[POSBLK_SIZE];
    int st = open_file(posblk, path);
    if (st != 0) die("open", st);
    st = do_insert(posblk, key, (unsigned char)tag);
    printf("insert key=%lu tag=%02x status=%d (%s)\n",
           (unsigned long)key, tag, st, status_name(st));
    { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }
}

static void cmd_insert_var(const char *path, DWORD key, unsigned total)
{
    char posblk[POSBLK_SIZE];
    unsigned char record[32768];
    unsigned char keybuf[KEY_SIZE];
    DWORD dlen;
    unsigned i;
    int st = open_file(posblk, path);
    if (st != 0) die("open", st);

    memset(record, 0, sizeof record);
    record[0] = (unsigned char)(key & 0xff);
    record[1] = (unsigned char)((key >> 8) & 0xff);
    record[2] = (unsigned char)((key >> 16) & 0xff);
    record[3] = (unsigned char)((key >> 24) & 0xff);
    for (i = 4; i < 22 && i < total; i++)
        record[i] = 0xEE;
    for (i = 22; i < total; i++)
        record[i] = (unsigned char)(0x80 + ((key * 7 + i) % 64));

    dlen = total;
    memset(keybuf, 0, sizeof keybuf);
    st = btrcall(B_INSERT, posblk, record, &dlen, keybuf, sizeof keybuf - 1, 0);
    printf("insert_var key=%lu total=%u status=%d (%s)\n",
           (unsigned long)key, total, st, status_name(st));
    { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }
}

static void cmd_get(const char *path, DWORD key)
{
    char posblk[POSBLK_SIZE];
    unsigned char tag = 0;
    int st = open_file(posblk, path);
    if (st != 0) die("open", st);
    st = do_get(posblk, key, &tag);
    printf("get key=%lu status=%d (%s) tag=%02x\n",
           (unsigned long)key, st, status_name(st), tag);
    { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }
}

/* B_GET_POSITION (op 22) is deliberately not exercised here -- see
 * wcclass_delete's comment for why. This command is kept only to confirm a
 * key resolves to a position at all (status 0). */
static void cmd_position(const char *path, DWORD key)
{
    char posblk[POSBLK_SIZE];
    int st = open_file(posblk, path);
    if (st != 0) die("open", st);
    st = do_get(posblk, key, NULL);
    printf("position: get key=%lu status=%d (%s)\n", (unsigned long)key, st, status_name(st));
    { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }
}

/* Core delete scenario: GET_EQUAL to position, print the position, DELETE,
 * report status, then attempt a GET_NEXT (does deleting disturb the cursor
 * enough to make GET_NEXT fail?) and a second DELETE with no reposition in
 * between (is the position still "current" after the first delete consumed
 * it?). Also re-reads the FCR's free-list head and record count via B_STAT
 * before and after, and a raw look at the freed slot's own bytes via the
 * `raw` command run separately (position printed here is what to pass it). */
static void cmd_delete(const char *path, DWORD key)
{
    char posblk[POSBLK_SIZE];
    DWORD pos = 0;
    int st = open_file(posblk, path);
    if (st != 0) die("open", st);

    st = do_get(posblk, key, NULL);
    printf("delete: get key=%lu status=%d (%s)\n", (unsigned long)key, st, status_name(st));
    if (st != 0) { fprintf(stderr, "FAIL: get before delete\n"); exit(1); }

    (void)pos; /* B_GET_POSITION dropped here -- see wcclass_delete's comment */

    st = do_delete(posblk);
    printf("delete: delete status=%d (%s)\n", st, status_name(st));

    st = btrcall(B_GET_NEXT, posblk, &(unsigned char[DATA_SIZE]){0}, &(DWORD){DATA_SIZE}, NULL, 0, 0);
    printf("delete: getnext-after-delete status=%d (%s)\n", st, status_name(st));

    st = do_delete(posblk);
    printf("delete: second-delete-no-reposition status=%d (%s)\n", st, status_name(st));

    { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }
}

/* Diagnostic only: `cmd_delete` above deletes a record from a file whose
 * inserts happened in EARLIER, separate process invocations (this probe's
 * usual per-command-open/close style). `xactprobe.c`'s working delete
 * scenarios always insert and delete within one continuous open -- this
 * command tests whether that difference is what a page fault seen from
 * `cmd_delete` was actually about: create, insert three, delete one, all in
 * a single session, self-contained. */
static void cmd_selfcontained_delete(const char *path)
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
    fs->pagesize = 2048;
    fs->indexes_raw = 1;
    fs->flags = 0;
    ks->position = 1;
    ks->length = 4;
    ks->flags = 0x0100;
    ks->ext_type = 0x0e;
    st = btrcall(B_CREATE, posblk, data, &dlen, keybuf, (BYTE)(strlen(keybuf) + 1), (char)0);
    printf("selfcontained: create status=%d (%s)\n", st, status_name(st));
    if (st != 0) exit(1);
    { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }

    st = open_file(posblk, path);
    if (st != 0) die("open", st);

    st = do_insert(posblk, 1, 0xAA);
    printf("selfcontained: insert key=1 status=%d (%s)\n", st, status_name(st));
    st = do_insert(posblk, 2, 0xBB);
    printf("selfcontained: insert key=2 status=%d (%s)\n", st, status_name(st));
    st = do_insert(posblk, 3, 0xCC);
    printf("selfcontained: insert key=3 status=%d (%s)\n", st, status_name(st));

    st = do_get(posblk, 2, NULL);
    printf("selfcontained: get key=2 status=%d (%s)\n", st, status_name(st));

    st = do_delete(posblk);
    printf("selfcontained: delete status=%d (%s)\n", st, status_name(st));

    /* Cursor behaviour right after the delete: does GET_NEXT still work, and
     * from where -- key 1 (before the deleted key 2) or key 3 (after it)?
     * keybuf is a real, non-NULL buffer even though GET_NEXT does not need
     * one -- B_STAT's `record_count()` needed the same workaround
     * (page-faulted with a NULL/0 key buffer; see its comment). */
    {
        unsigned char record[DATA_SIZE];
        unsigned char nextkeybuf[KEY_SIZE];
        DWORD dlen2 = DATA_SIZE;
        memset(record, 0, sizeof record);
        memset(nextkeybuf, 0, sizeof nextkeybuf);
        st = btrcall(B_GET_NEXT, posblk, record, &dlen2, nextkeybuf, sizeof nextkeybuf - 1, 0);
        printf("selfcontained: getnext-after-delete status=%d (%s) key_read=%lu\n",
               st, status_name(st),
               (unsigned long)(record[0] | (record[1] << 8) | (record[2] << 16) | ((unsigned long)record[3] << 24)));
    }

    /* Second delete with no reposition in between -- is the position the
     * first delete consumed still "current" enough to delete again? */
    st = do_delete(posblk);
    printf("selfcontained: second-delete-no-reposition status=%d (%s)\n", st, status_name(st));

    /* Reposition on the now-deleted key again, then delete right after that
     * failed reposition. */
    st = do_get(posblk, 2, NULL);
    printf("selfcontained: reget-deleted-key status=%d (%s)\n", st, status_name(st));
    st = do_delete(posblk);
    printf("selfcontained: delete-after-failed-reget status=%d (%s)\n", st, status_name(st));

    /* Insert a fresh key: does it reuse the slot key 2 freed? Answered from
     * the FCR afterward (`delprobe_fcr.py`), not from this call's own
     * status -- a status-0 insert says nothing about which slot it landed
     * in. */
    st = do_insert(posblk, 4, 0xDD);
    printf("selfcontained: insert key=4 (after delete) status=%d (%s)\n", st, status_name(st));

    { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }
}

static void cmd_delete_var(const char *path, DWORD key)
{
    char posblk[POSBLK_SIZE];
    unsigned char record[32768];
    unsigned char keybuf[KEY_SIZE];
    DWORD dlen;
    DWORD pos = 0;
    int st = open_file(posblk, path);
    if (st != 0) die("open", st);

    keybuf_from(keybuf, key);
    dlen = sizeof record;
    memset(record, 0, sizeof record);
    st = btrcall(B_GET_EQUAL, posblk, record, &dlen, keybuf, 4, 0);
    printf("delete_var: get key=%lu status=%d (%s) datalen=%lu\n",
           (unsigned long)key, st, status_name(st), (unsigned long)dlen);
    if (st != 0) { fprintf(stderr, "FAIL: get before delete_var\n"); exit(1); }

    (void)pos; /* B_GET_POSITION dropped here -- see wcclass_delete's comment */

    st = do_delete(posblk);
    printf("delete_var: delete status=%d (%s)\n", st, status_name(st));

    { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }
}

static void cmd_delete_no_position(const char *path)
{
    char posblk[POSBLK_SIZE];
    int st = open_file(posblk, path);
    if (st != 0) die("open", st);
    st = do_delete(posblk);
    printf("delete_no_position: status=%d (%s)\n", st, status_name(st));
    { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }
}

static void cmd_delete_missing_key(const char *path, DWORD key)
{
    char posblk[POSBLK_SIZE];
    int st = open_file(posblk, path);
    if (st != 0) die("open", st);
    st = do_get(posblk, key, NULL);
    printf("delete_missing_key: get key=%lu status=%d (%s) (expect 4, not found)\n",
           (unsigned long)key, st, status_name(st));
    st = do_delete(posblk);
    printf("delete_missing_key: delete-after-failed-get status=%d (%s)\n", st, status_name(st));
    { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }
}

/* Positions on key1, deletes it, then GET_NEXT: if key2 sorts after key1,
 * does GET_NEXT land on key2? Answers "what does delete do to the cursor" in
 * a file where there IS a well-defined next record. */
static void cmd_getnext_after_delete(const char *path, DWORD key1, DWORD key2)
{
    char posblk[POSBLK_SIZE];
    unsigned char record[DATA_SIZE];
    DWORD dlen;
    int st;

    st = open_file(posblk, path);
    if (st != 0) die("open", st);

    st = do_insert(posblk, key1, 0x11);
    printf("getnext_after_delete: insert key1=%lu status=%d (%s)\n", (unsigned long)key1, st, status_name(st));
    st = do_insert(posblk, key2, 0x22);
    printf("getnext_after_delete: insert key2=%lu status=%d (%s)\n", (unsigned long)key2, st, status_name(st));

    st = do_get(posblk, key1, NULL);
    printf("getnext_after_delete: get key1 status=%d (%s)\n", st, status_name(st));

    st = do_delete(posblk);
    printf("getnext_after_delete: delete key1 status=%d (%s)\n", st, status_name(st));

    dlen = DATA_SIZE;
    memset(record, 0, sizeof record);
    st = btrcall(B_GET_NEXT, posblk, record, &dlen, NULL, 0, 0);
    printf("getnext_after_delete: getnext status=%d (%s) key_read=%lu\n",
           st, status_name(st),
           (unsigned long)(record[0] | (record[1] << 8) | (record[2] << 16) | ((unsigned long)record[3] << 24)));

    { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }
}

/* Insert key1, note its position, delete it, insert key2 (a fresh key), note
 * ITS position. If Btrieve reuses freed slots, the two positions match. */
/* Whether a later insert reuses a freed slot cannot be read off
 * `B_GET_POSITION` here -- see wcclass_delete's comment on why that call is
 * avoided. Instead this reports enough for the CALLER to answer it from the
 * FCR alone (`tools/btrieve-oracle/delprobe_fcr.py`, run separately against
 * the closed file): insert key1, delete it (the free-list head should become
 * key1's own slot, since it is the only free entry), then insert key2. If
 * key2 reuses the freed slot, the one existing free entry is consumed and
 * the free-list head goes back to NOWHERE; if key2 lands somewhere new
 * instead, the free-list head is untouched and still names key1's old slot. */
static void cmd_reuse(const char *path, DWORD key1, DWORD key2)
{
    char posblk[POSBLK_SIZE];
    int st;

    st = open_file(posblk, path);
    if (st != 0) die("open", st);

    st = do_insert(posblk, key1, 0xAA);
    printf("reuse: insert key1=%lu status=%d (%s)\n", (unsigned long)key1, st, status_name(st));
    st = do_get(posblk, key1, NULL);
    printf("reuse: get key1 status=%d (%s)\n", st, status_name(st));

    st = do_delete(posblk);
    printf("reuse: delete key1 status=%d (%s)\n", st, status_name(st));

    st = do_insert(posblk, key2, 0xBB);
    printf("reuse: insert key2=%lu status=%d (%s)\n", (unsigned long)key2, st, status_name(st));

    { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }
}

/* B_STAT wants a real (non-NULL) key buffer to write into even though this
 * only reads the file spec back -- mirrors xactprobe.c's record_count()
 * comment; keynum -1 asks for the file spec rather than one key's. */
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

/* The delete scenario against a REAL shipped file rather than a freshly
 * `create`d one -- see the file header comment for why: a fresh `create`
 * leaves shadow-paired pages this probe would have to resolve by stamp, and
 * none of the shipped MajorMUD files are shaped that way. `WCCCLASS.DAT`
 * (copied to `path` by the caller, never the original -- same rule
 * `sweep.sh` follows) has 15 records, reclen 153, one 2-byte autoincrement
 * key at record byte 1. `key16` is that key's native value (1..15 here).
 *
 * Answers, in order: what GET_EQUAL/DELETE/GET_NEXT/second-DELETE report: a
 * full hex dump of the record BEFORE delete (for a human or a script to diff
 * against a `raw` dump of the same file offset after), the record count via
 * B_STAT before and after, and whether the count survives a close+reopen. */
/* Minimal reproduction: open, GET_EQUAL, DELETE, close -- nothing else --
 * to isolate whether the crash `cmd_wcclass_delete` hits is really about
 * B_DELETE on this file, or about something else in that function (the
 * B_STAT call before the GET_EQUAL, in particular). */
/* Minimal cursor/edge-case battery against a real shipped file, all within
 * ONE session and with no `B_STAT` call anywhere near the delete --
 * `cmd_wcclass_delete`'s crash turned out to be `record_count()`'s `B_STAT`
 * call landing right before a GET_EQUAL+DELETE pair, not `B_DELETE` itself
 * (`cmd_wcclass_delete_minimal` above, with no `B_STAT`, does not crash).
 * Answers: does GET_NEXT work right after a delete, and from where; does a
 * second DELETE with no reposition between the two succeed or fail; what does
 * DELETE give with no established position at all (fresh open, no GET yet). */
static void cmd_wcclass_edge_cases(const char *path, unsigned key16)
{
    char posblk[POSBLK_SIZE];
    unsigned char record[DATA_SIZE];
    unsigned char keybuf[KEY_SIZE];
    DWORD dlen;
    int st;

    /* "No established position at all" is NOT tested against this file: a
     * bare open-then-DELETE, with no B_STAT and no prior positioning call of
     * any kind, page-faulted inside WBTRV32.DLL specifically on this file
     * (reclen 153, autoincrement key) -- see `docs/delete-oracle-answer.md`.
     * The same call against this probe's own synthetic fixed-length rig
     * (`delete_no_position`, reclen 32, EXTTYPE unsigned-binary key) does
     * not crash and answers status 8 (invalid positioning) cleanly -- that
     * is the answer used for this question; it is not re-derived here. */

    st = open_file(posblk, path);
    if (st != 0) die("open", st);

    memset(keybuf, 0, sizeof keybuf);
    keybuf[0] = (unsigned char)(key16 & 0xff);
    keybuf[1] = (unsigned char)((key16 >> 8) & 0xff);
    dlen = DATA_SIZE;
    memset(record, 0, sizeof record);
    st = btrcall(B_GET_EQUAL, posblk, record, &dlen, keybuf, 2, 0);
    printf("edge: get key=%u status=%d (%s)\n", key16, st, status_name(st));
    if (st != 0) { fprintf(stderr, "FAIL: get\n"); exit(1); }

    st = do_delete(posblk);
    printf("edge: delete status=%d (%s)\n", st, status_name(st));

    dlen = DATA_SIZE;
    memset(record, 0, sizeof record);
    st = btrcall(B_GET_NEXT, posblk, record, &dlen, NULL, 0, 0);
    printf("edge: getnext-after-delete status=%d (%s) key_read=%u\n",
           st, status_name(st), st == 0 ? (unsigned)(record[0] | (record[1] << 8)) : 0);

    st = do_delete(posblk);
    printf("edge: second-delete-no-reposition status=%d (%s)\n", st, status_name(st));

    /* Reposition on the SAME (now-deleted) key again -- what does GET_EQUAL
     * give for a key that no longer exists, and does a DELETE right after
     * that failed GET give a distinct status from "no position at all"? */
    dlen = DATA_SIZE;
    memset(record, 0, sizeof record);
    st = btrcall(B_GET_EQUAL, posblk, record, &dlen, keybuf, 2, 0);
    printf("edge: reget-same-key-after-delete status=%d (%s)\n", st, status_name(st));
    st = do_delete(posblk);
    printf("edge: delete-after-failed-reget status=%d (%s)\n", st, status_name(st));

    { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }
}

/* Insert one raw `reclen`-byte record filled with `fillbyte`, key bytes left
 * as part of that fill (an autoincrement key like WCCCLASS.DAT's ignores
 * whatever is there and assigns its own value, so this does not need to
 * construct a real key). Used to answer "does insert reuse a freed slot" by
 * comparison with `raw` afterward: if the freed slot's own file offset now
 * holds this fill pattern, it was reused. */
/* TRUE back-to-back double delete, nothing at all in between (no GET_NEXT,
 * no reposition) -- `cmd_selfcontained_delete`'s "second-delete-no-
 * reposition" step turned out to not test this: a GET_NEXT ran between the
 * two deletes and repositioned onto the next record, so that second delete
 * removed a DIFFERENT, still-valid record rather than re-deleting an
 * already-gone position. This is the clean version of that question. */
/* Self-contained variable-length delete: create (reclen 22, pagesize 2048,
 * flags 0x0001, matching updprobe.c's WCCTEXT-shaped rig), insert one 500-
 * byte record (so it has a real fragment, not just the fixed part), delete
 * it, all in one session. Only asks for the status -- not proof either way
 * about whether the fragment page itself gets freed; that would need walking
 * the fragment chain before and after, which is out of scope for what this
 * delete investigation has to answer (see the file header's variable-length
 * scope note). */
static void cmd_selfcontained_delete_var(const char *path)
{
    char posblk[POSBLK_SIZE];
    char keybuf[KEY_SIZE];
    unsigned char data[sizeof(FileSpec) + sizeof(KeySpec)];
    FileSpec *fs = (FileSpec *)data;
    KeySpec *ks = (KeySpec *)(data + sizeof(FileSpec));
    unsigned char record[1024];
    DWORD dlen = sizeof data;
    int st;
    unsigned i;

    memset(posblk, 0, sizeof posblk);
    memset(data, 0, sizeof data);
    memset(keybuf, 0, sizeof keybuf);
    strncpy(keybuf, path, sizeof keybuf - 1);
    fs->reclen = 22;
    fs->pagesize = 2048;
    fs->indexes_raw = 1;
    fs->flags = 0x0001;
    ks->position = 1;
    ks->length = 4;
    ks->flags = 0x0100;
    ks->ext_type = 0x0e;
    st = btrcall(B_CREATE, posblk, data, &dlen, keybuf, (BYTE)(strlen(keybuf) + 1), (char)0);
    printf("selfcontained_var: create status=%d (%s)\n", st, status_name(st));
    if (st != 0) exit(1);
    { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }

    st = open_file(posblk, path);
    if (st != 0) die("open", st);

    memset(record, 0, sizeof record);
    record[0] = 1;
    for (i = 4; i < 22; i++) record[i] = 0xEE;
    for (i = 22; i < 500; i++) record[i] = (unsigned char)(0x80 + (i % 64));
    dlen = 500;
    memset(keybuf, 0, sizeof keybuf);
    st = btrcall(B_INSERT, posblk, record, &dlen, keybuf, sizeof keybuf - 1, 0);
    printf("selfcontained_var: insert (500 bytes) status=%d (%s)\n", st, status_name(st));

    memset(keybuf, 0, sizeof keybuf);
    keybuf[0] = 1;
    dlen = sizeof record;
    st = btrcall(B_GET_EQUAL, posblk, record, &dlen, keybuf, 4, 0);
    printf("selfcontained_var: get status=%d (%s) datalen=%lu\n", st, status_name(st), (unsigned long)dlen);

    st = do_delete(posblk);
    printf("selfcontained_var: delete status=%d (%s)\n", st, status_name(st));

    { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }
}

static void cmd_double_delete(const char *path)
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
    fs->pagesize = 2048;
    fs->indexes_raw = 1;
    fs->flags = 0;
    ks->position = 1;
    ks->length = 4;
    ks->flags = 0x0100;
    ks->ext_type = 0x0e;
    st = btrcall(B_CREATE, posblk, data, &dlen, keybuf, (BYTE)(strlen(keybuf) + 1), (char)0);
    printf("double_delete: create status=%d (%s)\n", st, status_name(st));
    if (st != 0) exit(1);
    { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }

    st = open_file(posblk, path);
    if (st != 0) die("open", st);

    st = do_insert(posblk, 1, 0xAA);
    printf("double_delete: insert key=1 status=%d (%s)\n", st, status_name(st));

    st = do_get(posblk, 1, NULL);
    printf("double_delete: get key=1 status=%d (%s)\n", st, status_name(st));

    st = do_delete(posblk);
    printf("double_delete: first delete status=%d (%s)\n", st, status_name(st));

    st = do_delete(posblk);
    printf("double_delete: SECOND delete, nothing in between, status=%d (%s)\n", st, status_name(st));

    { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }
}

static void cmd_raw_insert(const char *path, unsigned reclen, unsigned fillbyte)
{
    char posblk[POSBLK_SIZE];
    unsigned char record[DATA_SIZE];
    unsigned char keybuf[KEY_SIZE];
    DWORD dlen;
    int st;

    st = open_file(posblk, path);
    if (st != 0) die("open", st);

    memset(record, (int)fillbyte, sizeof record);
    dlen = reclen;
    memset(keybuf, 0, sizeof keybuf);
    st = btrcall(B_INSERT, posblk, record, &dlen, keybuf, sizeof keybuf - 1, 0);
    printf("raw_insert: reclen=%u fill=%02x status=%d (%s)\n", reclen, fillbyte, st, status_name(st));

    { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }
}

static void cmd_wcclass_delete_minimal(const char *path, unsigned key16)
{
    char posblk[POSBLK_SIZE];
    unsigned char record[DATA_SIZE];
    unsigned char keybuf[KEY_SIZE];
    DWORD dlen;
    int st;

    st = open_file(posblk, path);
    if (st != 0) die("open", st);

    memset(keybuf, 0, sizeof keybuf);
    keybuf[0] = (unsigned char)(key16 & 0xff);
    keybuf[1] = (unsigned char)((key16 >> 8) & 0xff);
    dlen = DATA_SIZE;
    memset(record, 0, sizeof record);
    st = btrcall(B_GET_EQUAL, posblk, record, &dlen, keybuf, 2, 0);
    printf("wcclass_delete_minimal: get key=%u status=%d (%s)\n", key16, st, status_name(st));
    if (st != 0) { fprintf(stderr, "FAIL: get\n"); exit(1); }

    st = do_delete(posblk);
    printf("wcclass_delete_minimal: delete status=%d (%s)\n", st, status_name(st));

    { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }
}

static void cmd_wcclass_delete(const char *path, unsigned key16)
{
    char posblk[POSBLK_SIZE];
    unsigned char record[DATA_SIZE];
    unsigned char keybuf[KEY_SIZE];
    DWORD dlen;
    DWORD pos = 0;
    int st;
    unsigned i;

    st = open_file(posblk, path);
    if (st != 0) die("open", st);

    printf("wcclass_delete: records-before=%lu\n", (unsigned long)record_count(posblk));

    memset(keybuf, 0, sizeof keybuf);
    keybuf[0] = (unsigned char)(key16 & 0xff);
    keybuf[1] = (unsigned char)((key16 >> 8) & 0xff);
    dlen = DATA_SIZE;
    memset(record, 0, sizeof record);
    st = btrcall(B_GET_EQUAL, posblk, record, &dlen, keybuf, 2, 0);
    printf("wcclass_delete: get key=%u status=%d (%s) datalen=%lu\n",
           key16, st, status_name(st), (unsigned long)dlen);
    if (st != 0) { fprintf(stderr, "FAIL: get before delete\n"); exit(1); }

    printf("wcclass_delete: record-before-delete:");
    for (i = 0; i < dlen; i++) {
        if (i % 16 == 0) printf("\n  %04x:", i);
        printf(" %02x", record[i]);
    }
    printf("\n");

    /* get_position (B_GET_POSITION) is deliberately NOT called here: tried
     * first, it page-faulted inside WBTRV32.DLL on this file (reclen 153,
     * unlike the 32-byte-reclen rig `cmd_position`/`cmd_delete` use it
     * against without issue) and left a `winedbg --auto` process hanging on
     * stdin, wedging the shared engine for every other probe until killed
     * by hand. Its return value is not needed here anyway -- see the file
     * header's note that it is an opaque API-level cookie, not this host's
     * own file-offset `position` convention. */
    (void)pos;

    st = do_delete(posblk);
    printf("wcclass_delete: delete status=%d (%s)\n", st, status_name(st));

    printf("wcclass_delete: records-after-delete-same-session=%lu\n", (unsigned long)record_count(posblk));

    /* GET_EQUAL for the same key again: gone? */
    memset(record, 0, sizeof record);
    dlen = DATA_SIZE;
    st = btrcall(B_GET_EQUAL, posblk, record, &dlen, keybuf, 2, 0);
    printf("wcclass_delete: get-after-delete status=%d (%s) (expect 4, not found)\n", st, status_name(st));

    /* Reposition on the deleted key (fails, per above), then try GET_NEXT
     * from wherever that left the cursor -- does a failed reposition leave
     * a usable position or not? */
    st = btrcall(B_GET_NEXT, posblk, record, &(DWORD){DATA_SIZE}, NULL, 0, 0);
    printf("wcclass_delete: getnext-after-failed-reget status=%d (%s)\n", st, status_name(st));

    /* Now reposition on a DIFFERENT surviving key and delete again with no
     * reposition in between -- answers "second delete, no reposition". */
    st = btrcall(B_GET_FIRST, posblk, record, &(DWORD){DATA_SIZE}, NULL, 0, 0);
    printf("wcclass_delete: get-first (surviving record) status=%d (%s)\n", st, status_name(st));
    st = do_delete(posblk);
    printf("wcclass_delete: delete (first surviving record) status=%d (%s)\n", st, status_name(st));
    st = do_delete(posblk);
    printf("wcclass_delete: second-delete-no-reposition status=%d (%s)\n", st, status_name(st));

    printf("wcclass_delete: records-after-second-delete-same-session=%lu\n", (unsigned long)record_count(posblk));

    { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }

    st = open_file(posblk, path);
    if (st != 0) die("reopen", st);
    printf("wcclass_delete: records-after-close-reopen=%lu\n", (unsigned long)record_count(posblk));
    { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }
}

/* GET_EQUAL `key`, rewrite every byte after the key field with `tag`, and
 * UPDATE. The key value itself is left alone, which is the whole point: it
 * separates "does an update move the DATA page" from "does an update move the
 * INDEX", questions a key-changing update would answer together and therefore
 * answer neither of. Pair it with `update_key` below. */
static void cmd_update(const char *path, DWORD key, unsigned char tag)
{
    char posblk[POSBLK_SIZE];
    unsigned char record[DATA_SIZE];
    unsigned char keybuf[KEY_SIZE];
    DWORD dlen;
    int st;
    unsigned i;

    st = open_file(posblk, path);
    if (st != 0) die("open", st);

    keybuf_from(keybuf, key);
    dlen = DATA_SIZE;
    memset(record, 0, sizeof record);
    st = btrcall(B_GET_EQUAL, posblk, record, &dlen, keybuf, 4, 0);
    printf("update: get key=%lu status=%d (%s) datalen=%lu\n",
           (unsigned long)key, st, status_name(st), (unsigned long)dlen);
    if (st != 0) { fprintf(stderr, "FAIL: get before update\n"); exit(1); }

    for (i = 4; i < RECLEN; i++)
        record[i] = tag;

    dlen = RECLEN;
    st = btrcall(B_UPDATE, posblk, record, &dlen, keybuf, 4, 0);
    printf("update: key=%lu newtag=%02x status=%d (%s) returned_dlen=%lu\n",
           (unsigned long)key, tag, st, status_name(st), (unsigned long)dlen);

    { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }
}

/* GET_EQUAL `oldkey`, overwrite the record's key field with `newkey`, and
 * UPDATE -- the case where the index genuinely has to change because the
 * record's ordered position did. Body bytes are left as the GET returned
 * them, so any byte that moves is attributable to the key change. */
static void cmd_update_key(const char *path, DWORD oldkey, DWORD newkey)
{
    char posblk[POSBLK_SIZE];
    unsigned char record[DATA_SIZE];
    unsigned char keybuf[KEY_SIZE];
    DWORD dlen;
    int st;

    st = open_file(posblk, path);
    if (st != 0) die("open", st);

    keybuf_from(keybuf, oldkey);
    dlen = DATA_SIZE;
    memset(record, 0, sizeof record);
    st = btrcall(B_GET_EQUAL, posblk, record, &dlen, keybuf, 4, 0);
    printf("update_key: get key=%lu status=%d (%s)\n",
           (unsigned long)oldkey, st, status_name(st));
    if (st != 0) { fprintf(stderr, "FAIL: get before update_key\n"); exit(1); }

    record[0] = (unsigned char)(newkey & 0xff);
    record[1] = (unsigned char)((newkey >> 8) & 0xff);
    record[2] = (unsigned char)((newkey >> 16) & 0xff);
    record[3] = (unsigned char)((newkey >> 24) & 0xff);

    dlen = RECLEN;
    st = btrcall(B_UPDATE, posblk, record, &dlen, keybuf, 4, 0);
    printf("update_key: %lu -> %lu status=%d (%s) returned_dlen=%lu\n",
           (unsigned long)oldkey, (unsigned long)newkey, st, status_name(st),
           (unsigned long)dlen);

    { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }
}

/* One GET_EQUAL, one DELETE, nothing else. `cmd_delete` above also runs a
 * GET_NEXT and a second DELETE to probe cursor semantics; both are harmless to
 * the file, but a byte-level before/after diff should be able to attribute
 * every changed page to exactly one operation, and that is not true of a
 * command that performs four. */
static void cmd_delete_only(const char *path, DWORD key)
{
    char posblk[POSBLK_SIZE];
    int st = open_file(posblk, path);
    if (st != 0) die("open", st);

    st = do_get(posblk, key, NULL);
    printf("delete_only: get key=%lu status=%d (%s)\n",
           (unsigned long)key, st, status_name(st));
    if (st != 0) { fprintf(stderr, "FAIL: get before delete\n"); exit(1); }

    st = do_delete(posblk);
    printf("delete_only: delete key=%lu status=%d (%s)\n",
           (unsigned long)key, st, status_name(st));

    { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }
}

/* Plain filesystem read, bypassing Btrieve entirely -- run AFTER a Btrieve
 * command has closed the file, in a separate invocation, so there is no
 * question of reading through the Microkernel's own cache instead of what
 * actually hit disk. */
static void cmd_raw(const char *path, long offset, unsigned len)
{
    FILE *f = fopen(path, "rb");
    unsigned char *buf;
    unsigned i;
    if (!f) { fprintf(stderr, "FAIL: cannot open %s for raw read\n", path); exit(1); }
    buf = (unsigned char *)malloc(len);
    if (fseek(f, offset, SEEK_SET) != 0) { fprintf(stderr, "FAIL: seek\n"); exit(1); }
    if (fread(buf, 1, len, f) != len) { fprintf(stderr, "FAIL: short read\n"); exit(1); }
    printf("raw %s @%ld len=%u:", path, offset, len);
    for (i = 0; i < len; i++) {
        if (i % 16 == 0) printf("\n  %04x:", i);
        printf(" %02x", buf[i]);
    }
    printf("\n");
    free(buf);
    fclose(f);
}

int main(int argc, char **argv)
{
    HMODULE dll;
    const char *cmd, *path;

    /* Unbuffered: several scenarios here crash WBTRV32.DLL outright (a real,
     * reproducible NULL-pointer fault inside the DLL, not this probe's own
     * bug -- see the delete/get_position comments above), and an unhandled
     * exception never runs C's normal atexit flush. Fully-buffered stdout
     * lost every printf made before such a crash, including the ones that
     * would have shown exactly how far the scenario got; this makes every
     * line visible the instant it is printed. */
    setvbuf(stdout, NULL, _IONBF, 0);

    if (argc < 3) {
        fprintf(stderr, "usage: delprobe <cmd> <file.DAT> ...\n");
        return 2;
    }
    cmd = argv[1];
    path = argv[2];

    if (!strcmp(cmd, "raw")) {
        if (argc < 5) { fprintf(stderr, "needs <offset> <len>\n"); return 2; }
        cmd_raw(path, strtol(argv[3], NULL, 0), (unsigned)strtoul(argv[4], NULL, 0));
        return 0;
    }

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
    } else if (!strcmp(cmd, "create_mod")) {
        cmd_create_mod(path);
    } else if (!strcmp(cmd, "create_var")) {
        cmd_create_var(path);
    } else if (!strcmp(cmd, "insert")) {
        if (argc < 5) { fprintf(stderr, "needs <key> <tag>\n"); return 2; }
        cmd_insert(path, (DWORD)strtoul(argv[3], NULL, 10), (unsigned)strtoul(argv[4], NULL, 0));
    } else if (!strcmp(cmd, "insert_var")) {
        if (argc < 5) { fprintf(stderr, "needs <key> <total>\n"); return 2; }
        cmd_insert_var(path, (DWORD)strtoul(argv[3], NULL, 10), (unsigned)strtoul(argv[4], NULL, 10));
    } else if (!strcmp(cmd, "get")) {
        if (argc < 4) { fprintf(stderr, "needs <key>\n"); return 2; }
        cmd_get(path, (DWORD)strtoul(argv[3], NULL, 10));
    } else if (!strcmp(cmd, "position")) {
        if (argc < 4) { fprintf(stderr, "needs <key>\n"); return 2; }
        cmd_position(path, (DWORD)strtoul(argv[3], NULL, 10));
    } else if (!strcmp(cmd, "delete")) {
        if (argc < 4) { fprintf(stderr, "needs <key>\n"); return 2; }
        cmd_delete(path, (DWORD)strtoul(argv[3], NULL, 10));
    } else if (!strcmp(cmd, "update")) {
        if (argc < 5) { fprintf(stderr, "needs <key> <newtag>\n"); return 2; }
        cmd_update(path, (DWORD)strtoul(argv[3], NULL, 10),
                   (unsigned char)strtoul(argv[4], NULL, 0));
    } else if (!strcmp(cmd, "update_key")) {
        if (argc < 5) { fprintf(stderr, "needs <oldkey> <newkey>\n"); return 2; }
        cmd_update_key(path, (DWORD)strtoul(argv[3], NULL, 10),
                       (DWORD)strtoul(argv[4], NULL, 10));
    } else if (!strcmp(cmd, "delete_only")) {
        if (argc < 4) { fprintf(stderr, "needs <key>\n"); return 2; }
        cmd_delete_only(path, (DWORD)strtoul(argv[3], NULL, 10));
    } else if (!strcmp(cmd, "delete_var")) {
        if (argc < 4) { fprintf(stderr, "needs <key>\n"); return 2; }
        cmd_delete_var(path, (DWORD)strtoul(argv[3], NULL, 10));
    } else if (!strcmp(cmd, "delete_no_position")) {
        cmd_delete_no_position(path);
    } else if (!strcmp(cmd, "delete_missing_key")) {
        if (argc < 4) { fprintf(stderr, "needs <key>\n"); return 2; }
        cmd_delete_missing_key(path, (DWORD)strtoul(argv[3], NULL, 10));
    } else if (!strcmp(cmd, "getnext_after_delete")) {
        if (argc < 5) { fprintf(stderr, "needs <key1> <key2>\n"); return 2; }
        cmd_getnext_after_delete(path, (DWORD)strtoul(argv[3], NULL, 10), (DWORD)strtoul(argv[4], NULL, 10));
    } else if (!strcmp(cmd, "reuse")) {
        if (argc < 5) { fprintf(stderr, "needs <key1> <key2>\n"); return 2; }
        cmd_reuse(path, (DWORD)strtoul(argv[3], NULL, 10), (DWORD)strtoul(argv[4], NULL, 10));
    } else if (!strcmp(cmd, "wcclass_delete")) {
        if (argc < 4) { fprintf(stderr, "needs <key16>\n"); return 2; }
        cmd_wcclass_delete(path, (unsigned)strtoul(argv[3], NULL, 10));
    } else if (!strcmp(cmd, "selfcontained_delete")) {
        cmd_selfcontained_delete(path);
    } else if (!strcmp(cmd, "wcclass_delete_minimal")) {
        if (argc < 4) { fprintf(stderr, "needs <key16>\n"); return 2; }
        cmd_wcclass_delete_minimal(path, (unsigned)strtoul(argv[3], NULL, 10));
    } else if (!strcmp(cmd, "wcclass_edge_cases")) {
        if (argc < 4) { fprintf(stderr, "needs <key16>\n"); return 2; }
        cmd_wcclass_edge_cases(path, (unsigned)strtoul(argv[3], NULL, 10));
    } else if (!strcmp(cmd, "raw_insert")) {
        if (argc < 5) { fprintf(stderr, "needs <reclen> <fillbyte>\n"); return 2; }
        cmd_raw_insert(path, (unsigned)strtoul(argv[3], NULL, 10), (unsigned)strtoul(argv[4], NULL, 0));
    } else if (!strcmp(cmd, "double_delete")) {
        cmd_double_delete(path);
    } else if (!strcmp(cmd, "selfcontained_delete_var")) {
        cmd_selfcontained_delete_var(path);
    } else {
        fprintf(stderr, "FAIL: unknown command %s\n", cmd);
        return 2;
    }

    { DWORD d = 0; char pb[POSBLK_SIZE] = {0}; btrcall(B_STOP, pb, NULL, &d, NULL, 0, 0); }
    return 0;
}
