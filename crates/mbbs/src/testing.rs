//! A machine stopped at a host call, for testing one shim at a time.
//!
//! The arguments are pushed by real 16-bit code rather than planted on the
//! stack, because where cdecl actually leaves them is half of what a shim has
//! to get right. A test that laid them out itself would agree with a shim that
//! read them wrongly.

use std::path::PathBuf;

use mbbs16::{Exit, FarPtr, Machine, Ret};

use crate::Host;
use crate::shims::{Shim, ShimError};

pub struct Fixture {
    pub machine: Machine,
    pub host: Host,
    scratch: u16,
    next: u16,
}

/// Where the sample files a shim reads live.
pub fn data() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data")
}

/// An empty directory a test may write into, under `target/`.
///
/// Some of what the host does is *install* a file rather than read one, and a
/// test of that has to have somewhere to put it that is neither the checked-in
/// sample directory nor the system temporary one. `target/` is both inside the
/// repository and already ignored by git.
///
/// Cleared on each call, so a test never sees what the last run left.
pub fn scratch(name: &str) -> PathBuf {
    let at = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/test-scratch")
        .join(name);
    let _ = std::fs::remove_dir_all(&at);
    std::fs::create_dir_all(&at).expect("a scratch directory");
    at
}

/// A scratch directory holding copies of `files` from [`data`].
///
/// What an install step needs: the module's own files, somewhere the test may
/// let the host change them.
pub fn scratch_with(name: &str, files: &[&str]) -> PathBuf {
    let at = scratch(name);
    for file in files {
        std::fs::copy(data().join(file), at.join(file)).expect("a sample file to copy");
    }
    at
}

impl Fixture {
    /// A host over the checked-in sample files.
    pub fn new() -> Self {
        Self::rooted(data())
    }

    /// A host over a directory of the test's choosing.
    ///
    /// For the few shims that *write* into a module's directory -- see
    /// [`scratch_with`] -- which must not be the checked-in one.
    pub fn rooted(root: PathBuf) -> Self {
        let mut machine = Machine::new().expect("16-bit machine");
        let host = Host::new(&mut machine, root).expect("host");
        let scratch = machine.alloc_segment(4096).expect("scratch");
        Self {
            machine,
            host,
            scratch,
            next: 0,
        }
    }

    /// A NUL-terminated string in scratch memory the module can address.
    pub fn text(&mut self, s: &str) -> FarPtr {
        self.bytes(s.as_bytes(), true)
    }

    /// Raw bytes in scratch memory, terminated or not.
    pub fn bytes(&mut self, bytes: &[u8], terminate: bool) -> FarPtr {
        let at = FarPtr {
            offset: self.next,
            selector: self.scratch,
        };
        let mut out = bytes.to_vec();
        if terminate {
            out.push(0);
        }
        self.machine.write(at, &out).expect("fits");
        self.next += out.len() as u16;
        at
    }

    /// Argument words in scratch memory, laid out as a `va_list` finds them.
    ///
    /// The same order and the same widths as [`Fixture::call`] pushes, which is
    /// the point: a test that formats the same words both ways is a test that
    /// the two sources agree.
    pub fn words(&mut self, words: &[u16]) -> FarPtr {
        let bytes: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        self.bytes(&bytes, false)
    }

    /// Somewhere to write, with nothing in it.
    pub fn buffer(&mut self, len: u16) -> FarPtr {
        self.bytes(&vec![0; usize::from(len)], false)
    }

    /// What a buffer holds, up to its terminator.
    pub fn read(&self, at: FarPtr) -> String {
        String::from_utf8_lossy(self.machine.read_cstr(at).expect("terminated")).into_owned()
    }

    /// Stop at a host call whose argument words are `args`, in declaration
    /// order.
    pub fn call(&mut self, args: &[u16]) {
        let mut code = Vec::new();
        for word in args.iter().rev() {
            code.push(0xb8); // mov $word, %ax
            code.extend_from_slice(&word.to_le_bytes());
            code.push(0x50); // push %ax
        }
        code.extend_from_slice(&[0x9a, 0, 0, 0, 0]); // lcall $CS, $thunk 0
        let at = code.len() - 4;
        code[at..at + 4].copy_from_slice(&self.machine.thunk_address(0).to_bytes());
        code.push(0xcb);

        self.machine.load_code(&code).expect("module fits");
        let entry = self.machine.code_ptr(0);
        assert!(matches!(
            self.machine.call(entry, &[]).expect("called"),
            Exit::Call { index: 0 }
        ));
    }

    /// Push `args` and run `shim` over them.
    pub fn invoke(&mut self, shim: Shim, args: &[u16]) -> Result<Ret, ShimError> {
        self.call(args);
        shim(&mut self.machine, &mut self.host)
    }

    /// A far pointer, as the two argument words it arrives in.
    pub fn far(at: FarPtr) -> [u16; 2] {
        [at.offset, at.selector]
    }
}
