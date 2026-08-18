use textscreen::cell::Cells;
use textscreen::widget::{Rect, Widget};

struct Fill(u8);

impl Widget for Fill {
    fn render(&self, area: Rect, buf: &mut Cells) {
        for row in area.row..area.row + area.rows {
            for col in area.col..area.col + area.cols {
                buf.put(row, col, self.0, 7);
            }
        }
    }
}

#[test]
fn a_widget_paints_only_inside_its_area() {
    let mut buf = Cells::blank(10, 4);
    Fill(b'x').render(Rect { col: 2, row: 1, cols: 3, rows: 2 }, &mut buf);
    assert_eq!(buf.line(0), "          ", "row above the area");
    assert_eq!(buf.line(1), "  xxx     ");
    assert_eq!(buf.line(2), "  xxx     ");
    assert_eq!(buf.line(3), "          ", "row below the area");
}

#[test]
fn put_outside_the_grid_is_dropped_not_a_panic() {
    // A widget handed a bad area must not take the process down; a config
    // editor that panics mid-edit loses the sysop's work.
    let mut buf = Cells::blank(4, 2);
    buf.put(99, 99, b'x', 7);
    assert_eq!(buf.text().matches('x').count(), 0);
}

#[test]
fn write_str_truncates_at_max_and_at_the_edge() {
    let mut buf = Cells::blank(8, 1);
    buf.write_str(0, 0, b"abcdefghij", 7, 5);
    assert_eq!(buf.line(0), "abcde   ", "max wins");

    let mut buf = Cells::blank(8, 1);
    buf.write_str(0, 6, b"abcdef", 7, 99);
    assert_eq!(buf.line(0), "      ab", "the right edge wins");
}
