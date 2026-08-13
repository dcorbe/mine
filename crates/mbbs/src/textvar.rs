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

use mbbs_ptr::ModulePtr;

use crate::abi::{Abi, Wg16};
use crate::heap::Heap;
use crate::shims::ShimError;

/// `MAJORBBS.H:33` -- maximum size of a text variable name, terminator
/// included.
pub const TVRSIZ: u16 = 16;

/// Bytes of `struct textvar`: the name, then the routine.
pub const TEXTVAR_SIZE: u16 = TVRSIZ + 4;

/// One registered text variable, read back out of the table.
///
/// Generic over `A` because [`TextVars::get_mem`] hands one back with
/// `varrou: Option<A::Ptr>`. Not `#[derive(Debug, Clone, PartialEq, Eq)]`:
/// the derive macros would bound the generated impls on `A: Trait` rather
/// than `A::Ptr: Trait` -- see `crates/mbbs/src/abi.rs`'s `Ret<A>` for the
/// same problem and fix. `A::Ptr` already carries every one of these bounds
/// through `mbbs_ptr::ModulePtr`'s own supertraits, so no extra `where`
/// clause is needed on the hand-written impls below.
pub struct TextVar<A: Abi = Wg16> {
    /// The name a message refers to it by. MajorMUD's is `MUDCHARINFO`.
    pub name: String,

    /// The module routine that produces the text, or `None` if it is null.
    ///
    /// **Null is legitimate**, and that is measured rather than assumed: the
    /// module tests `varrou` before calling it -- `mov ax,[es:bx+0x10]` then
    /// `or ax,[es:bx+0x12]` at `seg 23:0x22f5` -- so a null one is a row that
    /// produces nothing, not a row that is wrong.
    pub varrou: Option<A::Ptr>,
}

impl<A: Abi> Clone for TextVar<A> {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            varrou: self.varrou,
        }
    }
}

impl<A: Abi> PartialEq for TextVar<A> {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name && self.varrou == other.varrou
    }
}

impl<A: Abi> Eq for TextVar<A> {}

impl<A: Abi> std::fmt::Debug for TextVar<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TextVar")
            .field("name", &self.name)
            .field("varrou", &self.varrou)
            .finish()
    }
}

/// Every text variable that has been registered, in module memory.
///
/// # Generic core, `Wg16`-facade names
///
/// `at` is typed `A::Ptr` rather than `FarPtr` so this struct is genuinely
/// `TextVars<A>`. `len`/`is_empty`/`at` never touched a `Machine` and move
/// onto `impl<A: Abi> TextVars<A>` outright. `push`/`get` do read and write
/// module memory, so going generic changes their signature (`&mut A::Mem`/
/// `&A::Mem` and `&mut Heap<A>` in place of `&mut Machine`/`&mut Heap`) --
/// a real break for shim call sites built against the old ones. So both keep
/// their name and `Wg16` signature (delegating into the generic core through
/// [`Machine::mem`]/[`Machine::mem_mut`], the same shape `Globals::word`/
/// `Globals::write` use), and the generic core gets new names --
/// `push_mem`/`get_mem` -- naming the parameter that is actually new, the
/// same convention `Globals::word_mem`/`Globals::write_mem` set.
///
/// `A` defaults to [`Wg16`] so every existing caller keeps naming this type
/// as plain `TextVars`. Not `#[derive(Debug, Default)]`: the derive macros
/// bound `A: Debug`/`A: Default` on the impl, which `Wg16` (a bare marker
/// struct) does not satisfy -- see `crates/mbbs/src/abi.rs`'s `Ret<A>` for
/// the same problem and fix.
pub struct TextVars<A: Abi = Wg16> {
    /// Where the table is, or `None` before the first registration.
    at: Option<A::Ptr>,

    /// How many rows it has.
    count: u16,
}

impl<A: Abi> Default for TextVars<A> {
    fn default() -> Self {
        Self { at: None, count: 0 }
    }
}

impl<A: Abi> std::fmt::Debug for TextVars<A>
where
    A::Ptr: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TextVars")
            .field("at", &self.at)
            .field("count", &self.count)
            .finish()
    }
}

impl<A: Abi> TextVars<A> {
    /// How many text variables are registered.
    pub fn len(&self) -> u16 {
        self.count
    }

    /// Whether none are.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Where the table is, which is what belongs in the `txtvars` global.
    pub fn at(&self) -> Option<A::Ptr> {
        self.at
    }

    /// Add a row, growing the table by one record, against memory directly
    /// rather than a whole `Machine`.
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
    /// The `_mem` suffix is vestigial -- see the struct's own doc comment.
    /// Errors come back as [`ShimError::Failed`] rather than
    /// [`ShimError::BadPointer`] here: that variant carries `mbbs16`'s own
    /// `FarPtrError`, which a generic `A::Ptr::Error` is not.
    ///
    /// # Errors
    ///
    /// If the name is empty, if the table would outgrow a segment, or if the
    /// heap has no room.
    pub fn push_mem(
        &mut self,
        mem: &mut A::Mem,
        heap: &mut Heap<A>,
        name: &str,
        varrou: A::Ptr,
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
            .reserve(mem, size)
            .map_err(|e| ShimError::Failed(format!("register_textvar: {e}")))?;

        // Zeroed before anything is written into it. The original left whatever
        // the heap last held in the bytes past a short name's terminator; a
        // correct reader stops at the terminator either way, and a table whose
        // bytes are a function of what was registered is worth more than that
        // fidelity.
        grown
            .write(mem, &vec![0u8; usize::from(size)])
            .map_err(|e| ShimError::Failed(e.to_string()))?;

        if let Some(old) = self.at {
            let kept = usize::from(self.count) * usize::from(TEXTVAR_SIZE);
            let bytes = old
                .resolve(mem, kept)
                .map_err(|e| ShimError::Failed(e.to_string()))?
                .to_vec();
            grown
                .write(mem, &bytes)
                .map_err(|e| ShimError::Failed(e.to_string()))?;
            heap.free(old)
                .map_err(|e| ShimError::Failed(format!("register_textvar: {e}")))?;
        }

        let row = A::ptr_offset(grown, self.count * TEXTVAR_SIZE);

        // `stzcpy`, not `strncpy`: at most fifteen characters and always a
        // terminator. A name that fills the field is truncated rather than left
        // running into `varrou`. Written directly rather than through
        // `shims::text::write_cstr` -- that helper takes `&mut Machine`, which
        // this method deliberately does not have.
        let text = name.as_bytes();
        let take = text.len().min(usize::from(TVRSIZ) - 1);
        let mut named = text[..take].to_vec();
        named.push(0);
        row.write(mem, &named).map_err(|e| ShimError::Failed(e.to_string()))?;

        A::ptr_offset(row, TVRSIZ)
            .write(mem, &A::ptr_to_bytes(varrou))
            .map_err(|e| ShimError::Failed(e.to_string()))?;

        self.at = Some(grown);
        self.count += 1;
        Ok(self.count - 1)
    }

    /// Row `n`, read out of module memory, or `None` if there is no such row,
    /// against memory directly rather than a whole `Machine`.
    ///
    /// Read back every time rather than remembered. The table is memory the
    /// module can reach and change, so what it holds now is the answer.
    ///
    /// The `_mem` suffix is vestigial -- see the struct's own doc comment.
    ///
    /// # Errors
    ///
    /// If the table no longer names memory that can be read.
    pub fn get_mem(&self, mem: &A::Mem, n: u16) -> Result<Option<TextVar<A>>, ShimError> {
        let (Some(at), true) = (self.at, n < self.count) else {
            return Ok(None);
        };
        let row = A::ptr_offset(at, n * TEXTVAR_SIZE);
        let bytes = row
            .resolve(mem, usize::from(TEXTVAR_SIZE))
            .map_err(|e| ShimError::Failed(e.to_string()))?;

        // `name` is a fixed-width field, so it is read bounded rather than
        // scanned -- though unlike an agent's `appid` a name here always has a
        // terminator, because `stzcpy` guarantees one.
        let field = &bytes[..usize::from(TVRSIZ)];
        let end = field.iter().position(|b| *b == 0).unwrap_or(field.len());
        let name = String::from_utf8_lossy(&field[..end]).into_owned();

        // Null is checked on the raw bytes, before decoding: `A::Ptr` has no
        // generic notion of "null" to ask about after the fact, but "every
        // byte of the pointer field is zero" is the same test for any ABI
        // this crate has met, and it is what `FarPtr`'s own
        // `offset != 0 || selector != 0` check reduces to.
        let ptr_bytes = &bytes[usize::from(TVRSIZ)..usize::from(TEXTVAR_SIZE)];
        let varrou = A::ptr_from_bytes(ptr_bytes);
        let is_null = ptr_bytes.iter().all(|b| *b == 0);

        Ok(Some(TextVar {
            name,
            varrou: (!is_null).then_some(varrou),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::Fixture;
    // Wg16-only, and deliberately scoped to the fixtures rather than the
    // file: production code here reaches memory through `A::Ptr` now, so a
    // file-level import would be an unused one in the non-test build and a
    // standing invitation to reintroduce the coupling above.
    use mbbs16::FarPtr;

    #[test]
    fn an_empty_table_has_no_pointer_and_no_rows() {
        // `len`/`is_empty`/`at` moved onto `impl<A: Abi> TextVars<A>`, so
        // nothing here pins `A` to `Wg16` the way calling `push`/`get` would
        // -- unlike before this task, `TextVars`'s default type parameter no
        // longer resolves from a Wg16-only method used later in the test.
        let table: TextVars = TextVars::default();
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
            .push_mem(f.machine.mem_mut(), &mut f.host.heap, "MUDCHARINFO", varrou)
            .expect("registered");

        assert_eq!(n, 0, "the first text variable is number zero");
        assert_eq!(table.len(), 1);
        let row = table
            .get_mem(f.machine.mem(), 0)
            .expect("readable")
            .expect("a row");
        assert_eq!(row.name, "MUDCHARINFO");
        assert_eq!(row.varrou, Some(varrou));
    }
}
