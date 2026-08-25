//! Print a v6 Btrieve file's decoded structure in a stable, line-oriented,
//! diffable form -- one line per fact, sorted by physical page number, so
//! `diff` between two snapshots taken seconds apart (docs/2026-08-25-
//! btree-split-oracle.md's B-tree split/underflow oracle) shows exactly what
//! changed without hand-rolling a byte-level page decoder to re-derive it.
//!
//! Reuses `btrieve::read::file` -- the crate's own cited, corpus-measured
//! decoder -- rather than a second, parallel decode of the same bytes.
//!
//! USAGE
//!   dump-v6 <path>
//!
//! Keys are printed as hex and, when exactly 4 bytes, also as an unsigned
//! little-endian integer -- this oracle's own rig always uses a 4-byte
//! unsigned-binary key -- so a diff reads as key VALUES, not opaque bytes.

use std::env;
use std::fs;
use std::process::ExitCode;

use btrieve::model::{Control, V6RecordSlot};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn key_as_int(key: &[u8]) -> String {
    if key.len() == 4 {
        let v = u32::from_le_bytes([key[0], key[1], key[2], key[3]]);
        format!("{v}")
    } else {
        "?".to_string()
    }
}

fn opt_hex(v: Option<u32>) -> String {
    match v {
        Some(x) => decode_pos(x),
        None => "none".to_string(),
    }
}

/// A record position (`head`/`tail`, and a v6 free slot's forwarding
/// `next`) -- NOT the same field as a B-tree `child` pointer, which carries
/// a key tag in its top byte (`decode_child`). Printed plainly so a diff
/// shows the raw bits without inventing a tag/logical split this field
/// does not have.
fn decode_pos(raw: u32) -> String {
    if raw == 0xffff_ffff {
        "NOWHERE".to_string()
    } else {
        format!("{raw:#010x}")
    }
}

fn decode_child(raw: u32) -> String {
    if raw == 0xffff_ffff {
        "NOWHERE".to_string()
    } else {
        let tag = (raw >> 24) & 0xff;
        let logical = raw & 0x00ff_ffff;
        format!("raw={raw:#010x} tag={tag:#04x} logical={logical}")
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("usage: dump-v6 <path>");
        return ExitCode::from(2);
    }
    let bytes = match fs::read(&args[1]) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("FAIL: cannot read {}: {e}", args[1]);
            return ExitCode::from(1);
        }
    };

    let file = match btrieve::read::file(&bytes) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("FAIL: not a readable Btrieve file: {}", e.why);
            return ExitCode::from(1);
        }
    };

    println!("len={} page_size={}", file.len, file.id.page_size);

    match &file.control {
        Control::Single(_) => println!("control: v5 (single copy) -- this dumper is v6-only"),
        Control::Shadowed { live, live_is_page, .. } => {
            println!(
                "control: live_page={live_is_page} generation={} records={} pages={} \
                 free_v6={:#010x} write_counter={} usage_4c={} index_alloc_4e={} usage_52={}",
                live.generation,
                live.records,
                live.pages,
                live.free_v6,
                live.write_counter,
                live.usage_4c,
                live.index_alloc_4e,
                live.usage_52,
            );
        }
    }

    for (i, kd) in file.key_descriptors.iter().enumerate() {
        println!(
            "key[{i}] number={:#04x} root_page={} records={} attributes={:#06x} \
             key_length={} entry_size={} max_entries={} half_entries={} chain={}",
            kd.key_number, kd.root_page, kd.records, kd.attributes,
            kd.key_length, kd.entry_size, kd.max_entries, kd.half_entries, kd.chain,
        );
    }

    let mut blocks: Vec<_> = file.v6_allocation_blocks.iter().enumerate().collect();
    blocks.sort_by_key(|(i, _)| *i);
    for (bi, blk) in blocks {
        for (ei, e) in blk.live.entries.iter().enumerate() {
            let logical = bi as u32 * blk.live.entries.len() as u32 + ei as u32 + 1;
            println!(
                "alloc block={} logical={logical} marker={:#06x} physical={}",
                blk.live.block, e.marker, e.physical_page
            );
        }
    }

    let mut pages: Vec<_> = file.v6_pages.iter().collect();
    pages.sort_by_key(|p| p.physical_page);
    for p in pages {
        // Classified from which of the model's own mutually-exclusive
        // fields is populated -- read::file already disambiguated a
        // TAG_TEMPLATE/key-0-tag collision (both 0x8000) by walking each
        // key's tree from its root, which the tag byte alone cannot do; a
        // label derived from `p.tag` here would just reintroduce that
        // ambiguity by a different route.
        let kind = if p.content.is_some() {
            "DATA".to_string()
        } else if p.index.is_some() {
            format!("INDEX(key={:#04x})", (p.tag >> 8) & 0x7f)
        } else if p.acs.is_some() {
            "ACS".to_string()
        } else if p.fragment.is_some() {
            "VARIABLE".to_string()
        } else if p.orphan.is_some() {
            "ORPHAN".to_string()
        } else {
            format!("UNKNOWN(tag={:#06x})", p.tag)
        };
        println!(
            "page {} {kind} tag={:#06x} logical={} stamp={}",
            p.physical_page, p.tag, p.logical, p.stamp
        );
        if let Some(idx) = &p.index {
            println!(
                "  leftmost={} rightmost={} entries={}",
                decode_child(idx.leftmost),
                decode_child(idx.rightmost),
                idx.entries.len()
            );
            for (i, e) in idx.entries.iter().enumerate() {
                println!(
                    "  entry[{i}] key={} ({}) head={:#010x} tail={} child={}",
                    hex(&e.key),
                    key_as_int(&e.key),
                    e.head,
                    opt_hex(e.tail),
                    e.child.map(decode_child).unwrap_or_else(|| "absent".to_string()),
                );
            }
        }
        if let Some(data) = &p.content {
            for (i, slot) in data.slots.iter().enumerate() {
                match slot {
                    V6RecordSlot::Live { marker, body } => {
                        println!("  slot[{i}] LIVE marker={marker} body={}", hex(body));
                    }
                    V6RecordSlot::Free { next, fill } => {
                        println!(
                            "  slot[{i}] FREE next={} fill_nonzero={}",
                            decode_pos(*next),
                            fill.iter().any(|b| *b != 0)
                        );
                    }
                }
            }
        }
        if let Some(orphan) = &p.orphan {
            println!("  orphan bytes={}", orphan.len());
        }
    }

    ExitCode::SUCCESS
}
