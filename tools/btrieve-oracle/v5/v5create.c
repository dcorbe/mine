/*
 * v5create.c -- the actual v5.00c oracle client: CREATE a fresh .DAT,
 * OPEN it, INSERT one record, CLOSE. Never touches a shipped .DAT/.VIR
 * (obeys the oracle rule: we write, the oracle reads back -- this mints
 * into C:\SCRATCH, i.e. tmp/btvcompat/dos/scratch on the host side).
 *
 * As of 2026-08-15 this has never actually executed a Btrieve call: it
 * hits the SAME silent-compile failure documented in repro_dos_h_bug.c
 * (its `#include <dos.h>` is enough on its own -- none of the FileSpec/
 * KeySpec/btrcall content below is implicated). Once that is fixed, this
 * file is believed ready to run as-is: `btrcall()` is a standard small-
 * model `int 0x7B` BTRCALL wrapper (Btrieve's DOS TSR interface, GEMOS/
 * REGS/SREGS int86x calling convention per the 5.x Btrieve manual), and
 * main() drives B_CREATE -> B_OPEN -> B_INSERT -> B_CLOSE against
 * C:\SCRATCH\V5TEST.DAT with a single 8-byte-keyed 64-byte-record file.
 */
#include <dos.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef unsigned int WORD;
typedef unsigned long DWORD;
typedef unsigned char BYTE;

#define B_OPEN 0
#define B_CLOSE 1
#define B_INSERT 2
#define B_GET_FIRST 12
#define B_CREATE 14
#define B_STAT 15

#define POSBLK_SIZE 128
#define KEY_SIZE 256

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

struct btvdat {
    char *datbuf;
    WORD dbflen;
    char *posp38;
    char *posblk;
    WORD funcno;
    char *key;
    char keylen;
    char keyno;
    WORD *statpt;
    WORD magic;
};

WORD status;

WORD btrcall(WORD funcno, void *posblk, void *datbuf, DWORD *dlen, void *key, BYTE keylen, char keyno)
{
    union REGS regs;
    struct SREGS sregs;
    struct btvdat bd;

    bd.datbuf = (char *)datbuf;
    bd.dbflen = (WORD)(*dlen);
    bd.posp38 = ((char *)posblk) + 38;
    bd.posblk = (char *)posblk;
    bd.funcno = funcno;
    bd.key = (char *)key;
    bd.keylen = (char)keylen;
    bd.keyno = keyno;
    bd.statpt = &status;
    status = 0;
    bd.magic = 24950;

    regs.x.dx = (unsigned)&bd;
    segread(&sregs);
    sregs.ds = sregs.ss;
    int86x(0x7B, &regs, &regs, &sregs);
    *dlen = bd.dbflen;
    return status;
}

int btrieve_loaded(void)
{
    union REGS regs;
    struct SREGS sregs;
    regs.x.ax = 0x357B;
    segread(&sregs);
    int86x(0x21, &regs, &regs, &sregs);
    printf("get-vector 7B: ES=%04X BX=%04X\n", sregs.es, regs.x.bx);
    return 1;
}

int main(void)
{
    char posblk[POSBLK_SIZE];
    char keybuf[KEY_SIZE];
    unsigned char data[sizeof(FileSpec) + sizeof(KeySpec)];
    FileSpec *fs = (FileSpec *)data;
    KeySpec *ks = (KeySpec *)(data + sizeof(FileSpec));
    DWORD dlen;
    WORD st;
    char rec[64];

    printf("sizeof FileSpec=%u sizeof KeySpec=%u\n", sizeof(FileSpec), sizeof(KeySpec));
    btrieve_loaded();

    memset(posblk, 0, sizeof posblk);
    memset(keybuf, 0, sizeof keybuf);
    memset(data, 0, sizeof data);

    strcpy(keybuf, "C:\\SCRATCH\\V5TEST.DAT");

    fs->reclen = 64;
    fs->pagesize = 512;
    fs->indexes_raw = 1;
    fs->records = 0;
    fs->flags = 0;
    fs->dup_pointers = 0;
    fs->unused = 0;
    fs->allocations = 0;

    ks->position = 1;
    ks->length = 8;
    ks->flags = 0;
    ks->approx_count = 0;
    ks->ext_type = 0;
    ks->null_value = 0;
    ks->number = 0;
    ks->acs_number = 0;

    dlen = sizeof(FileSpec) + sizeof(KeySpec);
    st = btrcall(B_CREATE, posblk, data, &dlen, keybuf, (BYTE)(strlen(keybuf) + 1), 0);
    printf("CREATE status=%u\n", st);
    if (st != 0) {
        printf("create failed, aborting\n");
        return 1;
    }

    { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }

    memset(posblk, 0, sizeof posblk);
    memset(keybuf, 0, sizeof keybuf);
    strcpy(keybuf, "C:\\SCRATCH\\V5TEST.DAT");
    st = (WORD)btrcall(B_OPEN, posblk, NULL, &dlen, keybuf, (BYTE)(strlen(keybuf) + 1), 0);
    printf("OPEN status=%u\n", st);
    if (st != 0) return 1;

    memset(rec, 0, sizeof rec);
    strcpy(rec, "HELLOV5!");
    dlen = sizeof rec;
    st = btrcall(B_INSERT, posblk, rec, &dlen, keybuf, 0, 0);
    printf("INSERT status=%u\n", st);

    { DWORD d = 0; btrcall(B_CLOSE, posblk, NULL, &d, NULL, 0, 0); }

    printf("done\n");
    return 0;
}
