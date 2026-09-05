//! `struct usracc` and `struct keyrec`, byte for byte, plus the claim and
//! refusal types a listener and this host trade over an account.
//!
//! Everything here is pure: bytes in, bytes out, no [`crate::abi::Abi`], no
//! machine, no I/O. `struct usracc` is one account record -- `UStructs.h:20`
//! -- and its field offsets are identical whether the module reading it is a
//! `Wg16` or a `Wg32` build; only the record's total length differs (338
//! bytes vs. 304, both on-disk sizes: `USRACC.H`'s `USRACCSPARE` pads the
//! declared fields out to 338 for `Wg16`, and the 32-bit kit pads to 304
//! instead). `struct keyrec` is the key ring `LOCKNKEY.C` keeps beside it:
//! 30 bytes of owning userid, then a NUL-terminated, space-separated list of
//! key names.

/// What a listener learned about the caller's terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Terminal {
    pub ansi: bool,
    pub width: u8,
    pub height: u8,
}

/// What a listener claims about who is calling. Spec section 2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Login {
    Password { userid: String, password: String },
    Signup { userid: String, password: String },
    Trusted { userid: String, sysop: bool },
}

/// Why a claim was refused. Spec section 5. Closed: the listener maps
/// each to one wire line and nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    Unknown,
    BadPassword,
    NoPassword,
    Exists,
    Deleted,
    Suspended,
    Full,
    Maintenance,
    Invalid(&'static str),
}

/// `sizeof(userid)`, including the trailing NUL. `UStructs.h:10`.
pub const UIDSIZ: usize = 30;
/// `sizeof(psword)`, including the trailing NUL. `UStructs.h:11`.
pub const PSWSIZ: usize = 10;
/// A key (and class) name's size. `UStructs.h:8`.
pub const KEYSIZ: usize = 16;
/// Byte offset of the key list within a `keyrec`: the 30-byte owning
/// userid comes first. `LOCKNKEY.C:456` indexes `kysbuf[KLSTOF..]`.
pub const KLSTOF: usize = 30;
/// The largest a key ring's list is allowed to grow to. `addkyu`,
/// `LOCKNKEY.C:456`.
pub const RINGSZ: usize = 1024;
/// The first byte of a class ring's name. `LOCKNKEY.C:162`.
pub const RINGID: u8 = b'&';

/// `usracc.flags` bits, `USRACC.H:64-68`.
pub mod flags {
    pub const HASMST: u16 = 1;
    pub const UNDAXS: u16 = 2;
    pub const SUSPEN: u16 = 4;
    pub const DELTAG: u16 = 8;
}
/// `usracc.ansifl` bit, `USRACC.H:60`.
pub const ANSON: u8 = 1;

/// Byte offsets into `struct usracc`, identical for both ABIs. Spec Facts,
/// derived from `UStructs.h:20` field by field under Borland's default byte
/// alignment (no padding -- see `crates/mbbs/src/users.rs`'s module doc for
/// the measurement that this crate's other structs rely on the same rule).
pub mod at {
    /// `userid[UIDSIZ]`, `UStructs.h:21`.
    pub const USERID: usize = 0x00;
    /// `psword[PSWSIZ]`, `UStructs.h:22`, right after `userid`.
    pub const PSWORD: usize = 0x1e;
    /// `ansifl`, `UStructs.h:31`.
    pub const ANSIFL: usize = 0xd0;
    /// `scnwid`, `UStructs.h:32`.
    pub const SCNWID: usize = 0xd1;
    /// `scnbrk`, `UStructs.h:33`.
    pub const SCNBRK: usize = 0xd2;
    /// `scnfse`, `UStructs.h:34`.
    pub const SCNFSE: usize = 0xd3;
    /// `credat`, `UStructs.h:37`.
    pub const CREDAT: usize = 0xd6;
    /// `usedat`, `UStructs.h:38`.
    pub const USEDAT: usize = 0xd8;
    /// `flags`, `UStructs.h:40`.
    pub const FLAGS: usize = 0xdc;
    /// `prmcls[KEYSIZ]`, `UStructs.h:43`.
    pub const PRMCLS: usize = 0xf0;
    /// `curcls[KEYSIZ]`, `UStructs.h:44`.
    pub const CURCLS: usize = 0x100;
}

/// The bytes of one account record, at one ABI's stride (338 or 304).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Usracc {
    pub bytes: Vec<u8>,
}

impl Usracc {
    /// A brand-new account the way `SIGNUP.C:1204` leaves one, minus the
    /// class: `credat` and `usedat` today, `scnbrk` 24, everything else
    /// zero.
    pub fn new(stride: u16, userid: &str, password: &str, terminal: Terminal, today: u16) -> Self {
        let mut bytes = vec![0u8; stride as usize];

        let uid = userid.as_bytes();
        let ulen = uid.len().min(UIDSIZ - 1);
        bytes[..ulen].copy_from_slice(&uid[..ulen]);

        let pw = password.as_bytes();
        let plen = pw.len().min(PSWSIZ - 1);
        bytes[at::PSWORD..at::PSWORD + plen].copy_from_slice(&pw[..plen]);

        bytes[at::ANSIFL] = if terminal.ansi { ANSON } else { 0 };
        bytes[at::SCNWID] = terminal.width;
        bytes[at::SCNBRK] = 24;
        bytes[at::SCNFSE] = terminal.height;

        bytes[at::CREDAT..at::CREDAT + 2].copy_from_slice(&today.to_le_bytes());
        bytes[at::USEDAT..at::USEDAT + 2].copy_from_slice(&today.to_le_bytes());

        Self { bytes }
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Up to the first NUL. `str::from_utf8` rather than a true lossy
    /// conversion, because the return type borrows from `self` and cannot
    /// allocate a replacement string the way `String::from_utf8_lossy`
    /// would; invalid bytes read back as empty instead, the same fallback
    /// `crates/mbbs/src/dos.rs`'s `stem`/`ext` use for the same shape of
    /// field.
    pub fn userid(&self) -> &str {
        field_str(&self.bytes[at::USERID..at::USERID + UIDSIZ])
    }

    pub fn password(&self) -> &str {
        field_str(&self.bytes[at::PSWORD..at::PSWORD + PSWSIZ])
    }

    pub fn flags(&self) -> u16 {
        u16::from_le_bytes([self.bytes[at::FLAGS], self.bytes[at::FLAGS + 1]])
    }

    pub fn set_flags(&mut self, flags: u16) {
        self.bytes[at::FLAGS..at::FLAGS + 2].copy_from_slice(&flags.to_le_bytes());
    }

    pub fn curcls(&self) -> &str {
        field_str(&self.bytes[at::CURCLS..at::CURCLS + KEYSIZ])
    }

    pub fn usedat(&self) -> u16 {
        u16::from_le_bytes([self.bytes[at::USEDAT], self.bytes[at::USEDAT + 1]])
    }

    pub fn set_usedat(&mut self, packed: u16) {
        self.bytes[at::USEDAT..at::USEDAT + 2].copy_from_slice(&packed.to_le_bytes());
    }

    /// NUL-padded to `PSWSIZ`.
    pub fn set_password(&mut self, password: &str) {
        let field = &mut self.bytes[at::PSWORD..at::PSWORD + PSWSIZ];
        field.fill(0);
        let pw = password.as_bytes();
        let plen = pw.len().min(PSWSIZ - 1);
        field[..plen].copy_from_slice(&pw[..plen]);
    }

    /// `sameas`: case-insensitive, `MAJORBBS.C:2967`.
    pub fn password_matches(&self, offered: &str) -> bool {
        self.password().eq_ignore_ascii_case(offered)
    }

    /// The 30-byte key buffer a get-equal on key 0 takes.
    pub fn key(userid: &str) -> [u8; UIDSIZ] {
        let mut buf = [0u8; UIDSIZ];
        let uid = userid.as_bytes();
        let len = uid.len().min(UIDSIZ - 1);
        buf[..len].copy_from_slice(&uid[..len]);
        buf
    }
}

/// Bytes up to the first NUL in a fixed-size field, or the whole field if
/// none, decoded as UTF-8 -- or empty, if the bytes are not valid UTF-8.
fn field_str(field: &[u8]) -> &str {
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    std::str::from_utf8(&field[..end]).unwrap_or("")
}

/// One key ring record: userid, then a space-separated list. Spec Facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Keyrec {
    pub owner: String,
    pub keys: Vec<String>,
}

impl Keyrec {
    /// `KLSTOF + list + NUL`, at most `RINGSZ`. `addkyu`, `LOCKNKEY.C:456`.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Refusal> {
        let list = self.keys.join(" ");
        let total = KLSTOF + list.len() + 1;
        if total > RINGSZ {
            return Err(Refusal::Invalid("ring longer than RINGSZ"));
        }

        let mut bytes = vec![0u8; total];
        let owner = self.owner.as_bytes();
        let olen = owner.len().min(KLSTOF - 1);
        bytes[..olen].copy_from_slice(&owner[..olen]);
        bytes[KLSTOF..KLSTOF + list.len()].copy_from_slice(list.as_bytes());
        // The last byte is the ring's NUL terminator, already zero.

        Ok(bytes)
    }

    /// `setkeys`, `LOCKNKEY.C:188`: split on single spaces, drop empties.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let owner_field = &bytes[..KLSTOF.min(bytes.len())];
        let owner = field_str(owner_field).to_string();

        let rest = if bytes.len() > KLSTOF { &bytes[KLSTOF..] } else { &[][..] };
        let list = field_str(rest);
        let keys = list
            .split(' ')
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();

        Self { owner, keys }
    }

    /// `"&" + class`, at most `KEYSIZ` - 1 chars of class. `LOCKNKEY.C:162-163`.
    pub fn class_ring_name(class: &str) -> String {
        let limit = KEYSIZ - 1;
        let mut end = 0;
        for (idx, ch) in class.char_indices() {
            let next = idx + ch.len_utf8();
            if next > limit {
                break;
            }
            end = next;
        }
        let mut name = String::with_capacity(1 + end);
        name.push(RINGID as char);
        name.push_str(&class[..end]);
        name
    }
}

/// ASCII punctuation, C's `ispunct` under the "C" locale: graphic characters
/// that are neither letters nor digits.
fn is_ispunct(b: u8) -> bool {
    matches!(b, b'!'..=b'/' | b':'..=b'@' | b'['..=b'`' | b'{'..=b'~')
}

fn is_allowed_userid_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b',' | b'-' | b'\'' | b' ')
}

/// `valuid`, `SIGNUP.C:568`, with `fulalw` and `digalw` on and the length
/// bounds this host uses: 1 to `UIDSIZ` - 1 bytes.
pub fn validate_userid(userid: &str) -> Result<(), Refusal> {
    if userid.is_empty() {
        return Err(Refusal::Invalid("a user ID is required"));
    }
    if userid.len() > UIDSIZ - 1 {
        return Err(Refusal::Invalid("a user ID is at most 29 characters"));
    }

    let bytes = userid.as_bytes();
    let first = bytes[0];
    if first == b' ' || is_ispunct(first) {
        return Err(Refusal::Invalid("a user ID must start with a letter or digit"));
    }

    if !bytes.iter().all(|&b| is_allowed_userid_byte(b)) {
        return Err(Refusal::Invalid(
            "a user ID may contain letters, digits, spaces, periods, commas, hyphens and apostrophes",
        ));
    }

    if bytes.windows(2).any(|w| w[0] == b' ' && w[1] == b' ') {
        return Err(Refusal::Invalid("a user ID may not contain two spaces in a row"));
    }

    if ["new", "the", "off", "all"].iter().any(|reserved| userid.eq_ignore_ascii_case(reserved)) {
        return Err(Refusal::Invalid("that user ID is reserved"));
    }

    Ok(())
}

/// 1 to `PSWSIZ` - 1 bytes of printable ASCII.
pub fn validate_password(password: &str) -> Result<(), Refusal> {
    if password.is_empty() {
        return Err(Refusal::Invalid("a password is required"));
    }
    if password.len() > PSWSIZ - 1 {
        return Err(Refusal::Invalid("a password is at most 9 characters"));
    }
    if !password.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
        return Err(Refusal::Invalid(
            "a password may only contain printable ASCII characters",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_usracc_is_laid_out_at_the_spec_offsets() {
        let t = Terminal { ansi: true, width: 80, height: 24 };
        let u = Usracc::new(338, "Dan", "hunter2", t, 0x5d24);
        assert_eq!(u.bytes.len(), 338);
        assert_eq!(&u.bytes[0..3], b"Dan");
        assert_eq!(u.bytes[3], 0);
        assert_eq!(&u.bytes[at::PSWORD..at::PSWORD + 7], b"hunter2");
        assert_eq!(u.bytes[at::ANSIFL], ANSON);
        assert_eq!(u.bytes[at::SCNWID], 80);
        assert_eq!(u.bytes[at::SCNBRK], 24);
        assert_eq!(u.bytes[at::SCNFSE], 24);
        assert_eq!(u16::from_le_bytes([u.bytes[at::CREDAT], u.bytes[at::CREDAT + 1]]), 0x5d24);
        assert_eq!(u.usedat(), 0x5d24);
        assert_eq!(u.flags(), 0);
        assert_eq!(u.curcls(), "");
        assert!(u.bytes[at::FLAGS + 2..].iter().all(|&b| b == 0), "nothing past flags is written except the class fields, which are empty");
    }

    #[test]
    fn a_304_byte_stride_is_the_same_record_shorter() {
        let u = Usracc::new(304, "Dan", "x", Terminal { ansi: false, width: 80, height: 24 }, 1);
        assert_eq!(u.bytes.len(), 304);
        assert_eq!(u.bytes[at::ANSIFL], 0);
    }

    #[test]
    fn passwords_compare_like_sameas() {
        let u = Usracc::new(338, "Dan", "Hunter2", Terminal { ansi: true, width: 80, height: 24 }, 1);
        assert!(u.password_matches("hunter2"));
        assert!(u.password_matches("HUNTER2"));
        assert!(!u.password_matches("hunter"));
        assert!(!u.password_matches(""));
    }

    #[test]
    fn a_userid_longer_than_uidsiz_never_reaches_psword() {
        let long = "x".repeat(40);
        let u = Usracc::new(338, &long, "pw", Terminal { ansi: true, width: 80, height: 24 }, 1);
        assert_eq!(u.bytes[UIDSIZ - 1], 0, "byte 29 stays the NUL");
        assert_eq!(&u.bytes[at::PSWORD..at::PSWORD + 2], b"pw");
    }

    #[test]
    fn a_keyrec_round_trips_as_the_vendor_lays_it_out() {
        let k = Keyrec { owner: "Sysop".into(), keys: vec!["DEMO".into(), "NORMAL".into()] };
        let bytes = k.to_bytes().expect("fits");
        assert_eq!(bytes.len(), KLSTOF + "DEMO NORMAL".len() + 1);
        assert_eq!(&bytes[..5], b"Sysop");
        assert_eq!(&bytes[KLSTOF..], b"DEMO NORMAL\0");
        assert_eq!(Keyrec::from_bytes(&bytes), k);
        let empty = Keyrec { owner: "Ml".into(), keys: vec![] };
        assert_eq!(empty.to_bytes().expect("fits").len(), KLSTOF + 1, "an empty ring is 31 bytes, as the kit's Ml record is");
    }

    #[test]
    fn a_ring_past_ringsz_is_refused_not_truncated() {
        let k = Keyrec { owner: "Big".into(), keys: (0..200).map(|n| format!("KEY{n:04}")).collect() };
        assert_eq!(k.to_bytes(), Err(Refusal::Invalid("ring longer than RINGSZ")));
    }

    #[test]
    fn the_class_ring_name_is_ampersand_then_the_class() {
        assert_eq!(Keyrec::class_ring_name("SYSOP"), "&SYSOP");
        assert_eq!(Keyrec::class_ring_name(&"C".repeat(40)).len(), KEYSIZ, "RINGID plus KEYSIZ-1 of class, LOCKNKEY.C:157");
    }

    #[test]
    fn userids_follow_valuid() {
        assert_eq!(validate_userid("Dan"), Ok(()));
        assert_eq!(validate_userid("Dan Corbe"), Ok(()));
        assert_eq!(validate_userid("O'Neil-Smith, Jr."), Ok(()));
        assert!(validate_userid("").is_err());
        assert!(validate_userid(&"x".repeat(30)).is_err());
        assert!(validate_userid(" Dan").is_err());
        assert!(validate_userid("&SYSOP").is_err(), "a userid may not look like a keyring name");
        assert!(validate_userid("Dan  Corbe").is_err());
        assert!(validate_userid("Dan\tCorbe").is_err());
        assert!(validate_userid("New").is_err());
        assert!(validate_userid("off").is_err());
    }

    #[test]
    fn passwords_are_one_to_nine_printable_bytes() {
        assert_eq!(validate_password("a"), Ok(()));
        assert_eq!(validate_password("123456789"), Ok(()));
        assert!(validate_password("").is_err());
        assert!(validate_password("1234567890").is_err());
        assert!(validate_password("pa\x02ss").is_err());
    }
}
