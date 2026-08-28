-- MajorMUD (WCCMMUD.DLL) declarations lib.
--
-- See `scripts/lib/README.md` for the primitive surface this file is built
-- on (`mmud.bind`/`M.declare`, the pointer-handle methods, the scratch
-- budget) -- this file is that README's own worked example.
--
-- Every export name, record offset and calling recipe here is transcribed
-- from docs/2026-08-20-wccmmud-export-facts.md ("the doc"), which is the
-- authority: where memory of the earlier Rust milestone-1 code and the doc
-- disagree, the doc wins. Task 5 rewrites scripts/{cash,summon,setexp}.lua
-- to call into `M.grant_copper`/`M.deduct_wealth`/`M.summon`/
-- `M.set_experience` below -- this file has nothing that invokes itself.
--
-- Everything a script needs stays `local` or lives on `M`; nothing here
-- ever reads a bare, undefined global -- see the design doc's own
-- `namespace.rs` trap note: an unresolved bare global anywhere a lib's own
-- top-level code runs is live to the same soft-skip machinery a namespace
-- bind uses, and this file has no legitimate reason to reach for one.

local M = mmud.bind("wccmmud")

-- `_ADD_ITEM_TO_INVENTORY` is the one export whose shape differs per build
-- (doc, "The PE32 build"): five parameters on 16-bit, `(usrnum, 0, 0,
-- charges, item)`, but FOUR on PE32, `(usrnum, 0, charges, item)` -- every
-- one of the PE32 module's 13 call sites cleans 16 bytes, and its own
-- `sysop summon` handler pushes `item, -2, 0, usrnum`. Passing the 16-bit
-- shape to the PE32 export put the charges seed in the item-pointer slot
-- and the module dereferenced address 0xfffe (SIGSEGV at
-- `_add_item_to_inventory+0x39`, three times on the live board).
--
-- The charges seed is `-2` on both builds: the 16-bit call site's `0xfffe`
-- IS -2 at 16-bit width, and the PE32 site pushes `0xfffffffe`. Written
-- as `-2` so the `int` marshaller produces each ABI's own width of it.
local ADD_ITEM = ({
  wg16 = {
    sig = "int(int, int, int, int, ptr)",
    call = function(chan, item) return M.add_item_to_inventory(chan, 0, 0, -2, item) end,
  },
  wg32 = {
    sig = "int(int, int, int, ptr)",
    call = function(chan, item) return M.add_item_to_inventory(chan, 0, -2, item) end,
  },
})[mmud.abi]
if not ADD_ITEM then
  error("wccmmud.lua: the summon recipe is unmeasured for ABI " .. tostring(mmud.abi))
end

-- Six words, three far-pointer arguments (doc, "`_GET_ITEM_FROM_NAME` -- 6
-- words, 3 far-pointer arguments"): the search-name string, a shop-record
-- pointer (nil/nil = search the whole catalogue), and an OUT match-count
-- cell -- the same three arguments, one dword each, on PE32 (doc, "The
-- PE32 build"). `_ADDON_ADJUST_USER_WEALTH`'s amount is declared `long`
-- (doc, "Task 7 conflict"): a single Lua argument the marshaller itself
-- splits into low/high words, low word first -- exactly the
-- `CONCAT22(param_3, param_2)` shape the export wants, with no manual
-- splitting needed here.
M.declare {
  get_player              = "ptr(int)",
  save_player             = "int(int)",
  cleanup_currency        = "int(int)",
  addon_adjust_user_wealth = "int(int, long)",
  get_item_from_name      = "ptr(str, ptr, ptr)",
  add_item_to_inventory   = ADD_ITEM.sig,
}

-- `load_player` is declared nowhere here: neither the milestone-1 Rust
-- (`crates/mbbs-lua/src/lib.rs`, `crates/mbbs/src/extension.rs`) nor the
-- doc's own recipes ever call it. `_GET_PLAYER` alone resolves an
-- already-resident channel's record; nothing in this branch's ported
-- behaviour ever needed to force a load.

-- Record offsets, measured against the 16-bit build only
-- (docs/2026-08-20-wccmmud-export-facts.md, "The coin field layout" and
-- "Both offsets are 32-bit, low word first" + the controller's own
-- correction on the three-field experience invariant). The PE32 record has
-- NOT been measured -- the fsdfld precedent (23 vs 36 bytes for the same
-- struct under the two ABIs) says never assume the layout carries over.
-- Every helper below that touches one of these offsets gates on
-- `mmud.abi == "wg16"` first.
local REC = {
  loaded  = 0x1e,  -- doc: "_ADDON_ADJUST_USER_WEALTH ... tests pcVar3[0x1e] != '\0'"
  exp_raw = 0x3c,  -- / 0x3e -- the raw, unreduced total (32-bit, low word first)
  exp_mod = 0x46f, -- / 0x471 -- the same total MODULO 1,000,000,000
  exp_bil = 0x46b, -- / 0x46d -- the count of billions
  coin_lo = 0x613, -- / 0x615 -- the copper accumulator (32-bit, low word first)
  coin_hi = 0x615,
}

-- Every value written into these fields is `math.floor`-ed onto a whole
-- number and range-checked to `0 .. 0xffffffff` before it ever reaches a
-- record write or a declared `long` argument -- a fractional, negative, or
-- oversized typed value is an ordinary player mistake (a bad `cash`/`setexp`
-- line), not a script bug, and must be reported honestly rather than thrown
-- as an `mlua` error: a thrown argument-conversion error would disable the
-- whole command board-wide over one bad line of input (see the milestone-1
-- Rust `adjust_wealth`/`set_exp` doc comments this file replaces).
local function whole_u32(n)
  if type(n) ~= "number" or n ~= n or n == math.huge or n == -math.huge or n % 1 ~= 0 then
    return nil, "amount must be a whole number"
  end
  if n < 0 then
    return nil, "amount must not be negative"
  end
  if n > 0xffffffff then
    return nil, "amount is too large"
  end
  return math.floor(n)
end

-- `M.player(c)` -- the caller's own character record, or nil.
--
-- `_GET_PLAYER` never returns null for an in-range channel -- it indexes the
-- module's own per-channel slot table, and every in-range channel has a
-- slot whether or not anyone is playing on it. The module's own gate is the
-- flag byte at `+0x1e` (doc: "_ADDON_ADJUST_USER_WEALTH ... tests
-- pcVar3[0x1e] != '\0' before it will touch the record"); using anything
-- else here would mean a command typed at the login prompt writes into an
-- empty slot. Both failure cases (a nil handle, and a real handle whose
-- loaded flag is clear) report the SAME honest reason: the caller has no
-- way to act on which one happened, only that no character is loaded.
function M.player(c)
  if mmud.abi ~= "wg16" then return nil, "offsets unmeasured for this build" end

  local p = M.get_player(c.chan)
  if p == nil then
    return nil, "no character loaded on this channel"
  end
  if p:u8(REC.loaded) == 0 then
    return nil, "no character loaded on this channel"
  end
  return p
end

-- `M.set_experience(c, total)` -- overwrite (not add to) the caller's own
-- total experience.
--
-- There is no experience-setter export (doc, "Task 8 -- the experience
-- setter search, ANSWERED": every export touching experience is additive,
-- a pure calculator, or a display). Writing by offset is therefore the
-- correct route, not a shortcut around the tier-1 "prefer a module
-- accessor" rule.
--
-- THREE fields, not two, all written unconditionally every time (doc's own
-- CORRECTION, after the first draft stopped one step short of the module's
-- own `while` loop): `exp_raw` is the raw total; `exp_mod` is that total
-- MODULO 1,000,000,000; `exp_bil` is the count of billions. Skipping any
-- one of the three corrupts the character the next time
-- `_RESTRUCTURE_EXPERIENCE` runs (on load, on `experience`, on `st`, ...):
-- on a record whose own restructure flag is clear, writing only `exp_mod`/
-- `exp_bil` is silently reverted from `exp_raw` at the next load; on a
-- record whose flag is set (the normal state of any actively played
-- character), writing only `exp_raw` does nothing live, because
-- `_SHOW_STATUS` formats `exp_mod`/`exp_bil` straight to the screen with no
-- re-normalisation. `p:w32` writes low-endian bytes -- "low word first" is
-- exactly what that already does, with no manual word-splitting needed.
function M.set_experience(c, total)
  if mmud.abi ~= "wg16" then return nil, "offsets unmeasured for this build" end

  local exp, reason = whole_u32(total)
  if not exp then
    return false, reason
  end

  local record, player_reason = M.player(c)
  if not record then
    return false, player_reason
  end

  local BILLION = 1000000000
  record:w32(REC.exp_raw, exp)
  record:w32(REC.exp_mod, exp % BILLION)
  record:w32(REC.exp_bil, exp // BILLION)

  M.save_player(c.chan)
  return true
end

-- `M.grant_copper(c, n)` -- add `n` copper to the caller's own purse.
--
-- The game's own grant recipe (doc, "But granting is easy, and the game
-- does it in four places"): every in-game credit (`_SELL_ITEM`,
-- `_WITHDRAW_GOLD`, `_BORROW_GOLD`, `_CMD_GET`) does direct field
-- arithmetic on the copper accumulator, never through a shared export --
-- there is genuinely no "give user N coins" export among the 591 ordinals.
-- 32-bit add WITH CARRY at `coin_lo`/`coin_hi`, low word first, replicating
-- exactly what the module's own writers do:
--     new_low  = low + amount_lo                 (mod 2^16)
--     new_hi   = hi + amount_hi + carry(low+amount_lo)
-- then `cleanup_currency` normalises into higher denominations (mints
-- highest-denomination-first, already the minimum-coin-count -- and since
-- coin weight sums per-drawer count, minimum-weight -- representation, so
-- granting copper and letting it normalise needs no manual denomination
-- choice), then `save_player` persists it.
function M.grant_copper(c, n)
  if mmud.abi ~= "wg16" then return nil, "offsets unmeasured for this build" end

  local amount, reason = whole_u32(n)
  if not amount then
    return false, reason
  end

  local record, player_reason = M.player(c)
  if not record then
    return false, player_reason
  end

  local low = record:u16(REC.coin_lo)
  local hi = record:u16(REC.coin_hi)
  local amount_lo = amount & 0xffff
  local amount_hi = (amount >> 16) & 0xffff

  local sum = low + amount_lo
  local new_low = sum & 0xffff
  local carry = (sum > 0xffff) and 1 or 0
  local new_hi = (hi + amount_hi + carry) & 0xffff

  record:w16(REC.coin_lo, new_low)
  record:w16(REC.coin_hi, new_hi)

  M.cleanup_currency(c.chan)
  M.save_player(c.chan)
  return true
end

-- `M.deduct_wealth(c, n)` -- take `n` copper away from the caller's own
-- purse, refusing if they cannot afford it.
--
-- Asymmetric on purpose (doc, "Task 7 -- `cash`, and why the plan's single
-- export cannot deliver it"): `_ADDON_ADJUST_USER_WEALTH`'s whole body
-- forwards to `_DEDUCT_CURRENCY`, gated on an affordability check, every
-- coin write a decrement -- there is no path through it that credits a
-- player, which is why granting goes through `M.grant_copper`'s own
-- offset-poke recipe instead. This export saves the player itself (the
-- doc's own decompile: `_SAVE_PLAYER(param_1)` runs right after the
-- deduction), so this must NOT call `save_player` again. It returns a
-- `char`: 1 success, 0 refused (unaffordable, zero amount, or no character
-- loaded -- the export's own body gates on the same `+0x1e` flag `M.player`
-- does, but answers 0 rather than a distinct "not loaded" signal, so this
-- reports the same "insufficient funds" reason for either cause). Only the
-- low byte is meaningful on a `char` return -- mask, don't compare whole.
--
-- Touches no record offset -- by-name only, so no ABI gate.
function M.deduct_wealth(c, n)
  local amount, reason = whole_u32(n)
  if not amount then
    return false, reason
  end

  local result = M.addon_adjust_user_wealth(c.chan, amount)
  if result & 0xff ~= 0 then
    return true
  end
  return false, "insufficient funds"
end

-- `M.summon(c, name)` -- look `name` up via `get_item_from_name` and, on a
-- match, hand it to `add_item_to_inventory`. The whole sequence is
-- transcribed from the module's own undocumented `sysop summon <name>`
-- handler (doc, "Task 6 -- the two summon calls, derived from the module's
-- own SUMMON handler") -- copied, not invented.
--
-- Acquisition is NOT level-gated (doc: "Neither call enforces a level
-- requirement" -- that lives in `user_can_use`, reached only at wear/wield
-- time). What IS enforced is encumbrance, which is why this reads
-- `add_item_to_inventory`'s own return instead of discarding it the way
-- the module's own handler does (doc: "A bug in the original worth not
-- reproducing").
--
-- Touches no record offset -- by-name only, so no ABI gate.
function M.summon(c, name)
  -- An embedded NUL would truncate the C string the module reads at that
  -- byte, silently searching for a shorter, wrong name -- refuse outright.
  -- Lua strings are byte strings and do not forbid an embedded NUL; the
  -- declared `str` marshaller itself refuses one too, but as a thrown
  -- `mlua` error, which would disable `summon` board-wide over one bad
  -- line -- checked here first so this stays an ordinary, reported miss.
  if string.find(name, "\0", 1, true) then
    return false, "item name must not contain a NUL byte"
  end

  -- `c:buffer(2)` and this call's own `str` argument share one disjoint
  -- per-invocation scratch region (bind.rs's own fix), both drawn from the
  -- same fixed, small budget. A name long enough to exhaust it is a
  -- reachable player mistake (a stray paste, a key held down), not a
  -- script bug -- caught here, conservatively, rather than left to surface
  -- as a thrown "out of scratch" error from the marshaller, which this
  -- lib has no private knowledge of the exact byte budget for.
  if #name > 100 then
    return false, "item name too long"
  end

  -- Four bytes, not two: the PE32 build stores the match count as a dword
  -- (doc, "The PE32 build"); the 16-bit build's word lands in the low half
  -- of the zeroed cell, so one `u32` read is right on either ABI.
  local cell = c:buffer(4)
  local item = M.get_item_from_name(name, nil, cell)

  if item == nil then
    -- Null is ambiguous: it means EITHER "nothing matched" OR "several
    -- matched, and the module already printed its own disambiguation
    -- prompt" -- the OUT count cell is what tells them apart (doc: "Null
    -- return is ambiguous and the OUT count disambiguates it").
    local count = cell:u32(0)
    if count ~= 0 then
      -- Already handled by the module's own output -- say nothing more.
      return false, "ambiguous"
    end
    return false, "no such item"
  end

  -- The per-build call shape (`ADD_ITEM`, top of this file); `-2` is the
  -- charges seed, not a quantity or slot: it tells the module to take the
  -- item's own default charge count (doc: "`_ADD_ITEM_TO_INVENTORY` --
  -- the plan is exactly right").
  local ok = ADD_ITEM.call(c.chan, item)
  if ok & 0xff ~= 0 then
    return true
  end
  return false, "too heavy or no free slot"
end

return M
