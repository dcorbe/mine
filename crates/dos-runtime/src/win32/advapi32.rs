//! The ADVAPI32 subset this program actually calls: security descriptors.
//!
//! It builds one, and the reason is visible in what surrounds the calls: it has
//! just failed to open a named event and is about to create one. On NT a named
//! kernel object that other processes must reach needs a descriptor with a null
//! DACL, and this is that ritual.
//!
//! **Nothing here enforces anything, and that is honest rather than lazy.**
//! This host runs one program, as one user, with no other process to be
//! protected from; there is no access check for a descriptor to be the input
//! to. What the calls must do is *succeed* and leave behind bytes the program
//! can read back and hand onward, because the alternative -- failing -- sends
//! it down an error path that a real NT machine would never have taken.
//!
//! Every symbol here is stdcall, as all of Win32 is; see
//! [`crate::win32::kernel32`]'s doc comment on why the arity lives with the arm
//! that implements the symbol.

use mbbs_machine::m32::{Flat32Ptr, Machine, Memory};
use mbbs_machine::ptr::ModulePtr;

use crate::win32::kernel32::{Answer, FALSE, TRUE};
use crate::win32::process::Process;

/// `SECURITY_DESCRIPTOR_REVISION` -- the only revision Windows has ever had,
/// and the only one `InitializeSecurityDescriptor` accepts.
const SECURITY_DESCRIPTOR_REVISION: u32 = 1;

/// A self-relative-free, absolute `SECURITY_DESCRIPTOR` on a 32-bit target:
/// `Revision`, `Sbz1`, `Control`, then four pointers (`Owner`, `Group`, `Sacl`,
/// `Dacl`).
const SIZE_OF_SECURITY_DESCRIPTOR: usize = 20;

/// Byte offset of the `Control` word within that structure.
const CONTROL: u32 = 2;

/// Byte offset of the `Dacl` pointer within that structure.
const DACL: u32 = 16;

/// The cookie `RegisterEventSourceA` answers with. Any non-zero value serves;
/// a recognisable one makes it obvious in a trace.
const EVENT_SOURCE_HANDLE: u32 = 0x0047_4f4c;

/// `SE_DACL_PRESENT` -- the `Control` bit that says the `Dacl` field means
/// something. Without it a null `Dacl` reads as "no DACL, deny everyone"
/// rather than "null DACL, allow everyone", which are opposites.
const SE_DACL_PRESENT: u16 = 0x0004;

/// Answer an ADVAPI32 import, or `None` for one still unimplemented.
pub fn dispatch(
    process: &mut Process,
    machine: &mut Machine,
    mem: &mut Memory,
    symbol: &str,
) -> Option<Answer> {
    match symbol {
        // RegisterEventSourceA(LPCSTR lpUNCServerName, LPCSTR lpSourceName)
        //
        // The NT event log. A non-null cookie, because the only thing the
        // program does with the result is pass it to `ReportEventA` and test it
        // against NULL -- and a NULL would make it skip the report, which is
        // the one thing here worth *not* losing.
        "RegisterEventSourceA" => Some(Answer::stdcall(EVENT_SOURCE_HANDLE, 2)),
        // DeregisterEventSource(HANDLE)
        "DeregisterEventSource" => Some(Answer::stdcall(TRUE, 1)),
        // ReportEventA(HANDLE, WORD wType, WORD wCategory, DWORD dwEventID,
        //              PSID, WORD wNumStrings, DWORD dwDataSize,
        //              LPCSTR *lpStrings, LPVOID lpRawData)
        //
        // **Kept, not discarded.** This is the program telling an operator what
        // went wrong, in its own words. On a real NT box it lands in the event
        // log; here there is no log, so the alternative to keeping it is
        // throwing away the best diagnostic the program produces. Nine
        // arguments, and `lpStrings` is an *array of pointers* -- reading it as
        // a single string yields one line of rubbish instead of the message.
        "ReportEventA" => {
            let kind = machine.arg_u32(mem.stack(), 1);
            let id = machine.arg_u32(mem.stack(), 3);
            let count = machine.arg_u32(mem.stack(), 5);
            let strings = machine.arg_u32(mem.stack(), 7);
            let mut lines = Vec::new();
            for i in 0..count {
                let slot = strings.wrapping_add(i * 4);
                let Ok(bytes) = Flat32Ptr(slot).resolve(mem, 4) else {
                    break;
                };
                let ptr = u32::from_le_bytes(bytes.try_into().expect("4 bytes"));
                if let Some(s) = crate::win32::process::read_cstr(mem, ptr) {
                    lines.push(s);
                }
            }
            process.events.push(crate::win32::process::LoggedEvent {
                kind,
                id,
                strings: lines,
            });
            Some(Answer::stdcall(TRUE, 9))
        }
        // InitializeSecurityDescriptor(PSECURITY_DESCRIPTOR, DWORD dwRevision)
        "InitializeSecurityDescriptor" => {
            let at = machine.arg_u32(mem.stack(), 0);
            let revision = machine.arg_u32(mem.stack(), 1);
            Some(Answer::stdcall(
                initialize_security_descriptor(mem, at, revision),
                2,
            ))
        }
        // SetSecurityDescriptorDacl(PSECURITY_DESCRIPTOR, BOOL bDaclPresent,
        //                           PACL pDacl, BOOL bDaclDefaulted)
        "SetSecurityDescriptorDacl" => {
            let at = machine.arg_u32(mem.stack(), 0);
            let present = machine.arg_u32(mem.stack(), 1) != 0;
            let dacl = machine.arg_u32(mem.stack(), 2);
            Some(Answer::stdcall(
                set_security_descriptor_dacl(mem, at, present, dacl),
                4,
            ))
        }
        // SetKernelObjectSecurity(HANDLE, SECURITY_INFORMATION,
        //                         PSECURITY_DESCRIPTOR)
        //
        // Answers TRUE and keeps nothing. The descriptor would only ever be
        // consulted by an access check, and this host performs none -- see the
        // module doc comment. Storing it against the handle would record a fact
        // nothing can read, which is worse than not storing it: a later reader
        // would reasonably assume something enforced it.
        //
        // TRUE rather than FALSE because failure here is not neutral. The
        // program has just created the event it is securing, and a host that
        // refuses sends it into cleanup for a problem that does not exist.
        "SetKernelObjectSecurity" => Some(Answer::stdcall(TRUE, 3)),
        _ => None,
    }
}

/// `InitializeSecurityDescriptor` -- write a zeroed descriptor with its
/// revision set.
///
/// Zeroed is correct, not merely convenient: a freshly initialised descriptor
/// has no owner, no group and no ACLs, and every one of those is a null
/// pointer. Only the revision byte is not zero.
///
/// A revision other than 1 is refused, as Windows refuses it. That is the one
/// way this call can fail, and leaving it out would make the function
/// unfalsifiable.
fn initialize_security_descriptor(mem: &mut Memory, at: u32, revision: u32) -> u32 {
    if revision != SECURITY_DESCRIPTOR_REVISION {
        return FALSE;
    }
    let mut sd = vec![0u8; SIZE_OF_SECURITY_DESCRIPTOR];
    sd[0] = SECURITY_DESCRIPTOR_REVISION as u8;
    if Flat32Ptr(at).write(mem, &sd).is_err() {
        return FALSE;
    }
    TRUE
}

/// `SetSecurityDescriptorDacl` -- record the DACL and the bit that says it is
/// there.
///
/// The `Dacl` pointer is stored even when it is null, because a null DACL with
/// `SE_DACL_PRESENT` set is a specific, deliberate thing -- "everyone may do
/// anything" -- and is almost certainly what this program is asking for. Losing
/// the distinction between that and "no DACL at all" would be losing the whole
/// content of the call.
fn set_security_descriptor_dacl(mem: &mut Memory, at: u32, present: bool, dacl: u32) -> u32 {
    let Ok(control) = Flat32Ptr(at + CONTROL).resolve(mem, 2) else {
        return FALSE;
    };
    let mut bits = u16::from_le_bytes(control.try_into().expect("resolve returned 2 bytes"));
    if present {
        bits |= SE_DACL_PRESENT;
    } else {
        bits &= !SE_DACL_PRESENT;
    }
    if Flat32Ptr(at + CONTROL).write(mem, &bits.to_le_bytes()).is_err() {
        return FALSE;
    }
    if Flat32Ptr(at + DACL).write(mem, &dacl.to_le_bytes()).is_err() {
        return FALSE;
    }
    TRUE
}
