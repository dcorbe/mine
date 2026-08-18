//! The painter's whole job is emitting less than a full screen. These tests
//! watch what it emits, which taking an `impl Write` is what allows.

use textscreen::cell::{Cell, Cells};
use textscreen::paint::Painter;

fn paint(p: &mut Painter, grid: &Cells) -> String {
    let mut out = Vec::new();
    // Parked off column 1: every row address is `\x1b[{row};1H`, so a cursor
    // park at column 1 would be byte-identical to row 1's address and the
    // tests below that assert an address is *absent* would break by
    // coincidence. Column 79 makes that collision structurally impossible.
    p.paint(&mut out, grid, (0, 79), false).expect("write to a Vec");
    String::from_utf8(out).expect("painter emits UTF-8")
}

#[test]
fn the_first_paint_emits_every_row() {
    let grid = Cells::blank(80, 25);
    let mut p = Painter::new();
    let out = paint(&mut p, &grid);
    for row in 1..=25 {
        assert!(out.contains(&format!("\x1b[{row};1H")), "row {row} missing");
    }
}

#[test]
fn an_unchanged_repaint_emits_no_rows() {
    let grid = Cells::blank(80, 25);
    let mut p = Painter::new();
    let _ = paint(&mut p, &grid);
    let second = paint(&mut p, &grid);
    assert!(
        !second.contains("\x1b[1;1H"),
        "nothing changed, so no row should be addressed: {second:?}"
    );
}

#[test]
fn only_the_changed_row_is_repainted() {
    let mut grid = Cells::blank(80, 25);
    let mut p = Painter::new();
    let _ = paint(&mut p, &grid);

    grid.cells[3 * 80] = Cell { ch: b'A', attr: 7 };
    let out = paint(&mut p, &grid);

    assert!(out.contains("\x1b[4;1H"), "row 4 changed and must be addressed");
    assert!(!out.contains("\x1b[5;1H"), "row 5 did not change: {out:?}");
    assert!(!out.contains("\x1b[1;1H"), "row 1 did not change: {out:?}");
}

#[test]
fn dos_colour_order_is_remapped_not_passed_through() {
    // DOS counts blue as 1 and red as 4; ANSI the other way round. Attribute
    // 0x01 is blue on black, which is SGR 34 -- not 31.
    let mut grid = Cells::blank(1, 1);
    grid.cells[0] = Cell { ch: b'x', attr: 0x01 };
    let mut p = Painter::new();
    let out = paint(&mut p, &grid);
    assert!(out.contains(";34;40m"), "blue must become 34, got {out:?}");
}

#[test]
fn a_c0_byte_in_a_cell_paints_as_a_glyph() {
    // 0x11 in a cell is a left-pointing triangle. Emitting it as a control
    // byte would move the cursor instead of drawing an arrow.
    let mut grid = Cells::blank(1, 1);
    grid.cells[0] = Cell { ch: 0x11, attr: 7 };
    let mut p = Painter::new();
    let out = paint(&mut p, &grid);
    assert!(out.contains('\u{25c4}'), "expected an arrow glyph: {out:?}");
}
