# `scripts/lib/` -- declared-bindings reference

The primitive surface `crates/mbbs-lua` (specifically `bind.rs`, `namespace.rs`,
`ptr.rs`) exposes to a `scripts/lib/<module>.lua` file. This is a reference
card for writing one, not a tutorial -- read `scripts/lib/wccmmud.lua` for a
complete worked example, and
`docs/superpowers/specs/2026-08-27-lua-declared-bindings-design.md` plus its
supersession, `docs/superpowers/specs/2026-08-28-lua-thin-lib-split-design.md`,
for the design record behind this shape.

**The boundary a lib file must hold:** a `scripts/lib/<module>.lua` is the
*machine layer* only -- export signatures, per-ABI offsets and call shapes,
and (where a module has one) a typed record object over its raw memory. A
command's recipe and policy -- what a command accepts, what it prints, how it
decides to refuse -- belongs in the command script (`scripts/cash.lua`,
`scripts/setexp.lua`, `scripts/summon.lua`, ...), written in plain,
ABI-neutral Lua against the surface the lib returns. If you are tempted to
write `if mmud.abi == "wg16" then ... else ...` in a command script, or to put
player-facing text or input validation in a lib file, that is the split
inverting.

## Binding a namespace

```lua
local M = mmud.bind("wccmmud")
```

Called from inside `scripts/lib/<module>.lua`, once, at the top. By the time
this line runs, `namespace.rs`'s own `__index` handler has already confirmed a
module named `wccmmud` is loaded on this machine and that this lib file
exists -- `mmud.bind` itself only hard-errors (naming every loaded module) if
its argument does not match, which should not happen through the normal
`local mud = wccmmud` path a *script* uses; it is a defensive check, not the
seam that decides availability. `M` is a fresh, empty namespace table.

## Declaring exports

```lua
M.declare {
  get_player               = "ptr(int)",
  save_player              = "int(int)",
  cleanup_currency         = "int(int)",
  addon_adjust_user_wealth = "bool(int, long)",
  get_item_from_name       = "ptr(str, ptr, ptr)",
  add_item_to_inventory    = B.add_sig,
}
```

(`B.add_sig` above is not special syntax -- a declared value is just a Lua
string, so a lib file free to compute one per-ABI before calling `declare`.
`scripts/lib/wccmmud.lua` does exactly this for
`add_item_to_inventory`, whose argument count differs between the 16-bit and
PE32 call shapes: `"bool(int, int, int, int, ptr)"` on `wg16`,
`"bool(int, int, int, ptr)"` on `wg32`.)

Each value is a `"ret(arg, ...)"` signature over six types:

| type   | meaning | marshalling |
|--------|---------|-------------|
| `int`  | ABI-natural int | Lua number in `-32768..=65535`; a negative value is truncated to its 16-bit two's-complement pattern and sign-extended before narrowing to the ABI's own width (so `-1` reads back as all-ones at *either* ABI, not a naive zero-extension). A magnitude outside that range is refused -- declare `long` for the full 32-bit range. |
| `long` | `u32` | Plain non-negative `0..=0xffffffff`, no sign ambiguity. Split into low/high words by the marshaller on a 16-bit ABI; pushed as one dword on a 32-bit one. |
| `ptr`  | far/flat pointer | `nil` maps to this ABI's null pointer; a pointer-handle table resolves through the invocation's own handle registry; **anything else -- a raw Lua number above all -- is refused.** A pointer is never built from a number. |
| `str`  | C string | The Lua string's raw bytes, auto-copied NUL-terminated into the shared scratch region (see below). Refused if it contains an embedded NUL (would silently truncate what the module reads). |
| `bool` | return only | Valid as `ret`; refused as an argument type at bind time (`bind.rs`: `"arg N: bool is not a valid argument type in ..."`), the same as `void`. |
| `void` | return only | Valid as `ret`; refused as an argument type. |

`str` is refused as a return type -- there is no defined "returns a string"
contract. A declared export that returns something arrives back in Lua as:
`void` -> `nil`; `bool` -> a Lua boolean, masking the low byte of the return
register (`(lo & 0xff) != 0`) -- whatever the module left in the high bits of
its return value is not part of the contract; `int`/`long` -> a plain integer
(the register's raw bit pattern -- reinterpret sign yourself if the field is
signed); `ptr` -> a pointer handle, or `nil` for a null return.

## Name resolution: the four-spelling probe

A declared name is tried against the module's real export table as, in
order: the name as written, `_name`, `NAME` (upper case), `_NAME`. The first
one that resolves wins.

## Bind-time errors vs. call-time errors

**Bind time** -- `M.declare{...}` executing, at load: an unparseable
signature, a name already declared twice on this namespace, or a declared
name for which none of the four spellings resolve. All of these fail the
**whole script load** (the extension does not come up at all) -- by the time
`declare` runs, the module is already known loaded, so a name that does not
resolve means the declarations do not fit this build, and that has to be
loud.

**Call time** -- `M.some_export(...)` invoked from inside a command handler:
a wrong argument count, an argument that fails its type/range check, a stale
or forged `ptr` handle, a scratch-budget overflow, or (should it ever happen)
a cross-ABI rebind mismatch. All of these throw an ordinary Lua runtime
error, which `Extension::command` catches: it disables *that one command*
and reports once via `c:note`-equivalent boot/runtime notes -- it does not
fail the board. This is also why assigning to a player-record field (below)
throws on an out-of-range value rather than refusing quietly: it goes
through a declared/primitive write underneath. A command script therefore
validates untrusted input itself before it ever reaches a declared call or a
record assignment -- `scripts/cash.lua` and `scripts/setexp.lua` each carry a
`whole_u32` helper (whole number, `0..=0xffffffff`) for exactly this, and
`scripts/summon.lua` rejects a NUL-embedded or over-long item name before
calling `mud.find_item` (whose own NUL/length guard, inside
`scripts/lib/wccmmud.lua`, exists so the `str` marshaller never throws --
not to hand the player a reason). A thrown argument error would disable the
whole command over one bad line of input, not just refuse that one line.

## `mmud.abi`

`"wg16"` or `"wg32"` (`Abi::NAME`), set once when `mmud.bind`/`mmud.declare`
are installed. A lib file gates any offset or recipe it has not measured
against a build on this:

```lua
if mmud.abi ~= "wg16" then return nil, "offsets unmeasured for this build" end
```

## Pointer handles

A `ptr`-typed value -- a declared call's return, or a `c:buffer(n)` result --
is an opaque table with:

- `p:add(n)` -- a new handle `n` bytes forward. Refuses a negative offset or
  one that overflows the ABI's address space; never wraps.
- `p:u8(off)`, `p:u16(off)`, `p:u32(off)` -- read `off` bytes past `p`,
  little-endian, **unsigned**, zero-extended into a Lua integer.
- `p:w8(off, v)`, `p:w16(off, v)`, `p:w32(off, v)` -- write `v` at `off`,
  little-endian. **Unsigned only**: `v` must fit `0..=0xff`/`0xffff`/
  `0xffffffff` or the call is refused, not truncated. There is no signed
  write convenience -- encode your own two's-complement bit pattern first
  (`-1` is `0xffff` at 16 bits, `0xffff_ffff` at 32) the same way a signed
  *read* is yours to reinterpret.

A handle is unforgeable (no raw pointer number ever reaches Lua as data) and
dies with the invocation that minted it -- reusing one from an earlier
command errors rather than resolving to a live-but-wrong address.

## `c:buffer(n)`

`n` zeroed bytes of host scratch, handed back as a pointer handle -- the
usual way to give a declared call a writable OUT-parameter cell:

```lua
local cell = c:buffer(4)
local item = M.get_item_from_name(name, nil, cell)
local count = cell:u32(0)
```

(Four bytes and `u32`, not two and `u16`, even though the count fits in a
16-bit word: PE32 stores the match count as a dword, and a 16-bit word
written into a zeroed 4-byte cell lands in its low half either way -- see
`M.find_item` below, the real caller of this shape.)

## Building a record object over `ptr`

A lib file is free to wrap a raw pointer handle in a Lua metatable so a
command script never sees an offset, a width, or a `p:w32` call. This is not
a primitive Rust provides -- it is plain Lua over the handles and offsets
above -- but it is the shape `scripts/lib/wccmmud.lua` uses for the player
record, and it is the pattern to reach for whenever a lib file's record has
more than one or two fields:

```lua
function M.player(c)
  local handle = M.get_player(c.chan)
  if handle == nil or handle:u8(OFF.loaded) == 0 then
    return nil
  end
  return setmetatable({}, {
    __index = function(_, key)
      if key == "copper" then return handle:u32(OFF.copper) end
      -- ...
      error("player record has no field " .. tostring(key))
    end,
    __newindex = function(_, key, v)
      if key == "copper" then handle:w32(OFF.copper, v); return end
      error("player record has no writable field " .. tostring(key))
    end,
  })
end
```

`wccmmud.lua`'s actual `mud.player(c)` returns a record exposing exactly
three keys:

- `p.copper` -- a plain `u32` number, read and written directly at the
  module's copper offset.
- `p.experience` -- a *logical* field: the module stores total experience as
  three physical dwords that must always agree (a raw copy, plus the total
  split mod-1e9 into a "billions" word and a "modulus" word -- see the
  comment above `make_record` in `wccmmud.lua` for why). The getter
  reconstructs the one logical total from the two split words; the setter
  writes all three physical fields from the one number you assign.
- `p:save()` -- calls the module's own save export for this channel; not a
  field, a bound method (`p.save` returns a closure, so `p:save()` and
  `p.save()` both work, but the metatable exposes it as a method for the
  `p:save()` spelling used everywhere in the command scripts).

Any other key -- read or write, including an honest typo like `p.cooper` --
throws (`error("player record has no field ...")` /
`"... no writable field ..."`) rather than silently returning `nil` or
writing nothing. There is no fourth field; do not extend this record from a
command script.

**Validate before you assign.** A record's `__newindex` writes straight
through to `handle:w32`, which is a primitive write: an out-of-range value
(anything outside `0..=0xffffffff`, or not a whole number) throws, and a
thrown error inside a command handler disables *that command* board-wide
until the board restarts (see "Bind-time errors vs. call-time errors"
above). So `p.copper = amount` is only ever reached after the caller has
already validated `amount` is a non-negative whole number in range -- this
is why `scripts/cash.lua` and `scripts/setexp.lua` each run untrusted input
through their own `whole_u32` check first, and never pass a raw
`tonumber(c.args)` straight into a record field.

## `mud.find_item(c, name)` and `mud.add_item(chan, item)`

Two `wccmmud.lua`-specific conveniences built over the primitives above --
not part of the Rust-provided surface, but worth knowing as the pattern for
a lib file's own helper functions:

- `mud.find_item(c, name) -> (item, count)` -- looks an item up by name,
  hiding the `c:buffer(4)` OUT-param cell shown above. Returns the item
  handle (or `nil`) and the match count. A NUL-embedded or over-long name is
  refused *inside* `find_item` itself, before it ever reaches the `str`
  marshaller (which would otherwise throw), so it reads back as `(nil, 0)`
  for bad input -- indistinguishable from "no such item" by design; a
  command script that wants to tell those apart for the player (as
  `scripts/summon.lua` does, to print "not a valid item name.") checks the
  name itself before calling in.
- `mud.add_item(chan, item) -> bool` -- the ABI-neutral wrapper around
  `add_item_to_inventory`, whose *argument count* (not just its offsets)
  differs by ABI: five arguments on `wg16`, four on `wg32`. `wccmmud.lua`
  picks the right closure (`B.add`) and signature (`B.add_sig`) once, at
  load, keyed on `mmud.abi`, so `scripts/summon.lua` calls
  `mud.add_item(c.chan, item)` without knowing either shape exists.

## The shared 128-byte scratch budget

`c:buffer` and every `str` argument marshalled in the *same command
invocation* draw from one shared, fixed 128-byte region, at a running
per-invocation cursor -- not independent bookkeeping each. This is
deliberate: it is what keeps a `c:buffer` cell and a `str` argument in the
same call (`M.get_item_from_name(name, nil, cell)`, the canonical shape) from
silently landing on the same bytes. The budget resets to empty at the start
of every command invocation. A single write bigger than the whole 128-byte
region is always refused by `write_scratch` itself, which names both the
byte count requested and the region's 128-byte capacity, on either ABI.

**A cumulative overrun -- writing past what an earlier consumer in the same
invocation already claimed, through `p:w8/w16/w32` on a handle you already
hold -- behaves differently per ABI, and only one of the two is actually
safe:**

- **Wg16**: refused. `write_scratch`'s backing region is a dedicated 16-bit
  segment sized exactly 128 bytes (`ModuleMem::alloc_region` ->
  `Segments::alloc_segment`), and every access -- including a stray
  `p:w32(off, v)` at an `off` past 128 -- is bounded by that segment's own
  descriptor limit. There is no way to reach memory outside the region.
- **Wg32 -- KNOWN GAP, not a guarantee**: NOT refused. Wg32's
  `alloc_region` (`crates/mbbs/src/abi/wg32.rs`) is a bump allocation out of
  one large shared arena (`mbbs-machine/src/m32/mem.rs`'s `Memory::arena`,
  16 MiB in `mbbs-server`), and `Memory::read_at`/`write_at` bounds-check
  against the *whole arena*, not the 128-byte scratch region a handle
  logically owns. `p:w8/w16/w32` only know the raw pointer a handle closed
  over, never the byte-length `c:buffer(n)` allocated it with -- so
  `cell:w32(200, value)` on a Wg32 board silently lands 72 bytes past the
  scratch region, inside whatever else the arena is holding, and succeeds.
  This is a real gap against this house's own "runtime crashes are better
  than undefined behavior" rule -- it is not undefined behavior in the
  memory-safety sense (still a bounds-checked Rust slice write, just against
  the wrong bound), but it is exactly the kind of silent, wrong-address write
  that rule exists to rule out. The fix is length-carrying handles (a handle
  that remembers how many bytes it is allowed to touch, checked in
  `p:w8/w16/w32` themselves, independent of the arena's own bound) -- not
  implemented yet; treat any offset past a `c:buffer(n)`'s own `n`, or past
  128 minus what earlier consumers already took, as a bug in the *calling*
  Lua on a Wg32 board today, because nothing downstream will catch it for
  you.

Keep buffer sizes and string arguments conservative regardless of ABI --
there is no way to grow the region, and on Wg32 there is currently nothing
stopping you from writing past it by mistake.

## Soft-skip rules

A script's `local mud = wccmmud` (or a lib file's own `M.declare`'s probe)
distinguishes two very different failure kinds:

- **The module is absent from this machine, or `scripts/lib/<name>.lua` does
  not exist.** Soft skip: the whole script that tried the bind has its
  registrations (if any ran before the failed bind) discarded, one
  operator-facing note is recorded naming the script, the namespace it
  wanted, and which condition failed, and loading moves on to the next
  script. This is normal, expected operation for a multi-module `scripts/`
  directory running against a board that has not loaded every module.
- **The lib file itself errors** -- a Lua syntax error, `M.declare` failing
  to resolve a declared export, two scripts registering the same command
  name, or an accidental bare global read inside the lib (a missing `local`
  reads as an ordinary Lua `nil`-related error while a lib file's own
  top-level code runs, since the `__index` namespace handler is deliberately
  off for the duration of that one `.eval()`). This is a **hard boot
  failure**: the whole board refuses to start, naming the file and the
  error.

## Containment: this is not a sandbox

Neither a lib file's boot-time top-level code nor a command handler's body
is bounded against an infinite loop or unbounded allocation -- there is no
Lua instruction-budget hook anywhere in this stack. See
`crates/mbbs-lua/src/lib.rs`'s own crate doc, "Containment: what bounds a
script, and what does not," for the full statement of that trust model.
Short version: writing a lib file here is writing something the operator
will trust the way they'd trust a plugin, not code running inside a sandbox.
