/*
 * control_no_header.c -- diagnostic control for the v5.00c oracle link failure.
 *
 * Compiles and LINKS CLEANLY under Turbo C 2.01 (default/small model, no
 * flags): produces a 190-byte OBJ with a real PUBDEF _main and a working
 * 2310-byte EXE. Confirms the toolchain (TCC.EXE, TLINK.EXE, C0S.OBJ,
 * CS.LIB) is intact and the small-model startup path works end to end.
 *
 * See repro_dos_h_bug.c for the one-line change that breaks it.
 */
int main(void)
{
    return 0;
}
