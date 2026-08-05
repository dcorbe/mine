//! The text-variable table, which lives in memory the module can reach.
//!
//! A *text variable* is a substitution MajorBBS performs on its way to a
//! channel: a module registers a name and a routine, and the routine's return
//! value replaces the name wherever a message mentions it.
//!
//! # Why this is not a `Vec`
//!
//! [`crate::Agent`] is a `Vec` on the host, because the module never sees the
//! agent table. This one is different, and the module's own code is what says
//! so. `WCCMMUD.DLL` addresses `txtvars` at ten sites, and every one of them
//! looks like `seg 23:0x2306`:
//!
//! ```text
//! les bx,[es:txtvars]          ; the far pointer, out of the host global
//! add bx,ax                    ; ax = index * 20
//! call word far [es:bx+0x10]   ; call varrou
//! ```
//!
//! So the table is walked by the module, through the pointer the host publishes
//! in `txtvars` -- and a host that kept its rows on the Rust side while leaving
//! that global null would be claiming to provide something it had not.
//!
//! # The layout is measured twice
//!
//! `MAJORBBS.H:279` declares `struct textvar { char name[TVRSIZ]; char
//! *(*varrou)(); }` with `TVRSIZ` 16, and the module independently indexes
//! `varrou` at `+0x10`. Twenty bytes, which is the `imul ax,ax,0x14` the host's
//! own `register_textvar` uses throughout.

use mbbs16::{FarPtr, Machine};

use crate::heap::Heap;
use crate::shims::ShimError;
use crate::shims::text::write_cstr;

/// `MAJORBBS.H:33` -- maximum size of a text variable name, terminator
/// included.
pub const TVRSIZ: u16 = 16;

/// Bytes of `struct textvar`: the name, then the routine.
pub const TEXTVAR_SIZE: u16 = TVRSIZ + 4;

/// One registered text variable, read back out of the table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextVar {
    /// The name a message refers to it by. MajorMUD's is `MUDCHARINFO`.
    pub name: String,

    /// The module routine that produces the text, or `None` if it is null.
    ///
    /// **Null is legitimate**, and that is measured rather than assumed: the
    /// module tests `varrou` before calling it -- `mov ax,[es:bx+0x10]` then
    /// `or ax,[es:bx+0x12]` at `seg 23:0x22f5` -- so a null one is a row that
    /// produces nothing, not a row that is wrong.
    pub varrou: Option<FarPtr>,
}

/// Every text variable that has been registered, in module memory.
#[derive(Debug, Default)]
pub struct TextVars {
    /// Where the table is, or `None` before the first registration.
    at: Option<FarPtr>,

    /// How many rows it has.
    count: u16,
}

impl TextVars {
    /// How many text variables are registered.
    pub fn len(&self) -> u16 {
        self.count
    }

    /// Whether none are.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Where the table is, which is what belongs in the `txtvars` global.
    pub fn at(&self) -> Option<FarPtr> {
        self.at
    }

    /// Add a row, growing the table by one record.
    ///
    /// Returns the new row's index, which is what `register_textvar` hands the
    /// module back.
    ///
    /// Grown **one record at a time**, which is what the original did
    /// (`alcmem` for the first, then `alcrsz` from `n*20` to `(n+1)*20`). The
    /// growth is quadratic in the number of variables and that is fine: a
    /// period board registered a few dozen, and the module reloads the pointer
    /// on every access -- `les bx,[es:txtvars]` -- so a table that moves is a
    /// table it follows.
    ///
    /// # Errors
    ///
    /// If the name is empty, if the table would outgrow a segment, or if the
    /// heap has no room.
    pub fn push(
        &mut self,
        machine: &mut Machine,
        heap: &mut Heap,
        name: &str,
        varrou: FarPtr,
    ) -> Result<u16, ShimError> {
        if name.is_empty() {
            return Err(ShimError::Failed(
                "register_textvar: a text variable with no name".to_owned(),
            ));
        }

        // In 32 bits, because a table of 3,277 rows overflows the `u16` the
        // heap takes and wrapping would allocate a table far too small to hold
        // what is then written into it.
        let size = (u32::from(self.count) + 1) * u32::from(TEXTVAR_SIZE);
        let size = u16::try_from(size).map_err(|_| {
            ShimError::Failed(format!(
                "register_textvar: {} text variables will not fit in a segment",
                self.count + 1
            ))
        })?;

        let grown = heap
            .alloc(machine, size)
            .map_err(|e| ShimError::Failed(format!("register_textvar: {e}")))?;

        // Zeroed before anything is written into it. The original left whatever
        // the heap last held in the bytes past a short name's terminator; a
        // correct reader stops at the terminator either way, and a table whose
        // bytes are a function of what was registered is worth more than that
        // fidelity.
        machine.write(grown, &vec![0u8; usize::from(size)])?;

        if let Some(old) = self.at {
            let kept = usize::from(self.count) * usize::from(TEXTVAR_SIZE);
            let bytes = machine.resolve(old, kept)?.to_vec();
            machine.write(grown, &bytes)?;
            heap.free(old)
                .map_err(|e| ShimError::Failed(format!("register_textvar: {e}")))?;
        }

        let row = FarPtr {
            offset: grown.offset + self.count * TEXTVAR_SIZE,
            selector: grown.selector,
        };

        // `stzcpy`, not `strncpy`: at most fifteen characters and always a
        // terminator. A name that fills the field is truncated rather than left
        // running into `varrou`.
        let text = name.as_bytes();
        let take = text.len().min(usize::from(TVRSIZ) - 1);
        write_cstr(machine, row, &text[..take], TVRSIZ)?;

        machine.write(
            FarPtr {
                offset: row.offset + TVRSIZ,
                ..row
            },
            &varrou.to_bytes(),
        )?;

        self.at = Some(grown);
        self.count += 1;
        Ok(self.count - 1)
    }

    /// Row `n`, read out of module memory, or `None` if there is no such row.
    ///
    /// Read back every time rather than remembered. The table is memory the
    /// module can reach and change, so what it holds now is the answer.
    ///
    /// # Errors
    ///
    /// If the table no longer names memory that can be read.
    pub fn get(&self, machine: &Machine, n: u16) -> Result<Option<TextVar>, ShimError> {
        let (Some(at), true) = (self.at, n < self.count) else {
            return Ok(None);
        };
        let row = FarPtr {
            offset: at.offset + n * TEXTVAR_SIZE,
            selector: at.selector,
        };
        let bytes = machine.resolve(row, usize::from(TEXTVAR_SIZE))?;

        // `name` is a fixed-width field, so it is read bounded rather than
        // scanned -- though unlike an agent's `appid` a name here always has a
        // terminator, because `stzcpy` guarantees one.
        let field = &bytes[..usize::from(TVRSIZ)];
        let end = field.iter().position(|b| *b == 0).unwrap_or(field.len());
        let name = String::from_utf8_lossy(&field[..end]).into_owned();

        let at = usize::from(TVRSIZ);
        let varrou = FarPtr {
            offset: u16::from_le_bytes([bytes[at], bytes[at + 1]]),
            selector: u16::from_le_bytes([bytes[at + 2], bytes[at + 3]]),
        };
        Ok(Some(TextVar {
            name,
            varrou: (varrou.offset != 0 || varrou.selector != 0).then_some(varrou),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::Fixture;

    #[test]
    fn an_empty_table_has_no_pointer_and_no_rows() {
        let table = TextVars::default();
        assert_eq!(table.len(), 0);
        assert!(table.is_empty());
        assert_eq!(table.at(), None);
    }

    #[test]
    fn a_row_is_read_back_out_of_module_memory() {
        // Read back rather than remembered, the same as `Registration::entry`
        // and for the same reason: the table is memory the module can reach, so
        // what it says now is the answer and what it said at registration is
        // not.
        let mut f = Fixture::new();
        let varrou = FarPtr {
            offset: 0x001e,
            selector: f.machine.code_selector(),
        };
        let mut table = TextVars::default();
        let n = table
            .push(&mut f.machine, &mut f.host.heap, "MUDCHARINFO", varrou)
            .expect("registered");

        assert_eq!(n, 0, "the first text variable is number zero");
        assert_eq!(table.len(), 1);
        let row = table.get(&f.machine, 0).expect("readable").expect("a row");
        assert_eq!(row.name, "MUDCHARINFO");
        assert_eq!(row.varrou, Some(varrou));
    }
}
