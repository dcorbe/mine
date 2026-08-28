# `scripts/lib/` -- declared-bindings reference

The primitive surface `crates/mbbs-lua` (specifically `bind.rs`, `namespace.rs`,
`ptr.rs`) exposes to a `scripts/lib/<module>.lua` file. This is a reference
card for writing one, not a tutorial -- read `scripts/lib/wccmmud.lua` for a
complete worked example, and
`docs/superpowers/specs/2026-08-27-lua-declared-bindings-design.md` for the
design record behind this shape.

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
  get_player = "ptr(int)",
  save_player = "int(int)",
  addon_adjust_user_wealth = "int(int, long)",
}
```

Each value is a `"ret(arg, ...)"` signature over five types:

| type   | meaning | marshalling |
|--------|---------|-------------|
| `int`  | ABI-natural int | Lua number in `-32768..=65535`; a negative value is truncated to its 16-bit two's-complement pattern and sign-extended before narrowing to the ABI's own width (so `-1` reads back as all-ones at *either* ABI, not a naive zero-extension). A magnitude outside that range is refused -- declare `long` for the full 32-bit range. |
| `long` | `u32` | Plain non-negative `0..=0xffffffff`, no sign ambiguity. Split into low/high words by the marshaller on a 16-bit ABI; pushed as one dword on a 32-bit one. |
| `ptr`  | far/flat pointer | `nil` maps to this ABI's null pointer; a pointer-handle table resolves through the invocation's own handle registry; **anything else -- a raw Lua number above all -- is refused.** A pointer is never built from a number. |
| `str`  | C string | The Lua string's raw bytes, auto-copied NUL-terminated into the shared scratch region (see below). Refused if it contains an embedded NUL (would silently truncate what the module reads). |
| `void` | return only | Valid as `ret`; refused as an argument type. |

`str` is refused as a return type -- there is no defined "returns a string"
contract. A declared export that returns something arrives back in Lua as:
`void` -> `nil`; `int`/`long` -> a plain integer (the register's raw bit
pattern -- reinterpret sign yourself if the field is signed); `ptr` -> a
pointer handle, or `nil` for a null return.

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
fail the board. This is exactly why the offset/range validation in
`scripts/lib/wccmmud.lua`'s own helpers (`whole_u32`, the NUL check in
`M.summon`) reports ordinary `false, reason` pairs instead of just letting a
bad player input reach a declared call and throw: a thrown argument error
would disable the whole command over one bad line of input, not just refuse
that one line.

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
local cell = c:buffer(2)
local item = M.get_item_from_name(name, nil, cell)
local count = cell:u16(0)
```

## The shared 128-byte scratch budget

`c:buffer` and every `str` argument marshalled in the *same command
invocation* draw from one shared, fixed 128-byte region, at a running
per-invocation cursor -- not independent bookkeeping each. This is
deliberate: it is what keeps a `c:buffer` cell and a `str` argument in the
same call (`M.get_item_from_name(name, nil, cell)`, the canonical shape) from
silently landing on the same bytes. The budget resets to empty at the start
of every command invocation. Running past what is left is refused outright,
never silently truncated -- a single write bigger than the whole 128-byte
region is refused by `write_scratch` itself, which names both the byte count
requested and the region's 128-byte capacity; a write that only overflows
because of what earlier consumers in the same invocation already took is
refused by the same bounds check `p:w8/w16/w32` goes through. Keep buffer
sizes and string arguments conservative -- there is no way to grow the
region.

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
