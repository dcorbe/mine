/*
 * repro_dos_h_bug.c -- minimal, isolated reproduction of the Task 7 blocker.
 *
 * FINDING (2026-08-15): the link failure a previous session hit while
 * building a v5.00c Btrieve client --
 *
 *     Undefined symbol '_main' in module C0S
 *
 * -- is NOT a memory-model mismatch between the client and C0S.OBJ (Turbo
 * C's small-model startup object). That was the leading hypothesis going
 * in and it is now RULED OUT:
 *
 *   - Explicit `-ms` (small model, matching C0S) on the compile: same error.
 *   - Manual `TLINK C0S+V5CREATE,V5CREATE,,EMU+MATHS+CS` (the small-model
 *     library set, by hand): same error.
 *
 * The real cause: merely `#include <dos.h>` -- with NO use of anything it
 * declares -- makes TCC.EXE 2.01 silently emit an OBJ with segment
 * definitions but ZERO PUBDEFs and ZERO code (no _main, no _TEXT content).
 * TCC reports no error, no warning; it prints "vN memory" and exits 0.
 * TLINK then correctly complains that C0S's call to _main can't be
 * resolved, because the OBJ genuinely never defined it. The "_main
 * undefined" message is a downstream SYMPTOM; the real failure is silent
 * and happens during compilation of this file, before code generation.
 *
 * Reproduced twice, in two independent DOSBox sessions:
 *   - control_no_header.c (no #include at all): PUBDEF _main present, links,
 *     produces a working 2310-byte EXE.
 *   - this file (#include <dos.h>, otherwise identical): PUBDEF _main
 *     absent, 190-byte OBJ (header records only), link fails as above.
 *
 * A run through CPP.EXE (the standalone preprocessor) shows dos.h itself
 * preprocesses cleanly to its true end (251 lines, matches `wc -l DOS.H`)
 * with no directive errors -- so this is not a corrupt/truncated dos.h and
 * not a preprocessor-stage crash. The break is somewhere in TCC's
 * declaration-parsing pass over dos.h's actual C content (structs, unions,
 * `_Cdecl`/`far` function prototypes) that leaves the compiler's internal
 * state such that it either never reaches or never emits the subsequent
 * function definition -- with no diagnostic surfaced through the normal
 * (redirected) stdout channel.
 *
 * NOT YET DONE (this is exactly where a next attempt should start):
 * bisect dos.h to find the specific declaration that trips this. A naive
 * line-range split does not work as-is -- dos.h opens an include-guard
 * `#ifdef`/`#ifndef` around line 14 whose `#endif` is past line 130, so
 * truncating the file breaks conditional-compilation nesting before the
 * real bug is ever reached (confirmed: produces an unrelated "Unexpected
 * end of file in conditional started on line 14" error). The right way to
 * bisect: preprocess dos.h through CPP.EXE FIRST (removing all directives),
 * then binary-search the flat, directive-free output, feeding each half to
 * TCC.EXE with a bare `int main(void){return 0;}` appended. See build.sh's
 * `bisect` target, which is scaffolded but not run -- doing so was out of
 * this task's timebox.
 */
#include <dos.h>

int main(void)
{
    return 0;
}
