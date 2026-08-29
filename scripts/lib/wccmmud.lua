-- MajorMUD (WCCMMUD.DLL) machine layer.
--
-- This file is the ONLY place that knows the module's export names, its
-- per-ABI record offsets, and its per-ABI call shapes. Everything above it
-- -- scripts/{cash,setexp,summon}.lua -- is ABI-neutral policy written in
-- plain Lua against the surface this file returns. See
-- docs/superpowers/specs/2026-08-28-lua-thin-lib-split-design.md and
-- scripts/lib/README.md. Offsets are measured in
-- docs/2026-08-20-wccmmud-export-facts.md.

local M = mmud.bind("wccmmud")

-- The ONLY wg16/wg32 literals in the whole tree. Defined before declare so
-- declare can use B.add_sig (add_item_to_inventory's arg count is per-ABI).
local B = ({
  wg16 = {
    add_sig = "bool(int, int, int, int, ptr)",
    add     = function(chan, item) return M.add_item_to_inventory(chan, 0, 0, -2, item) end,
    off     = { loaded = 0x1e, copper = 0x613, exp_raw = 0x3c, exp_mod = 0x46f, exp_bil = 0x46b },
  },
  wg32 = {
    add_sig = "bool(int, int, int, ptr)",
    add     = function(chan, item) return M.add_item_to_inventory(chan, 0, -2, item) end,
    off     = { loaded = 0x1e, copper = 0x620, exp_raw = 0x3c, exp_mod = 0x474, exp_bil = 0x470 },
  },
})[mmud.abi] or error("wccmmud.lua: unmeasured ABI " .. tostring(mmud.abi))

local OFF = B.off

M.declare {
  get_player               = "ptr(int)",
  save_player              = "int(int)",
  cleanup_currency         = "int(int)",
  addon_adjust_user_wealth = "bool(int, long)",
  get_item_from_name       = "ptr(str, ptr, ptr)",
  add_item_to_inventory    = B.add_sig,
}

M.add_item = B.add

local BILLION = 1000000000

-- The player record as a typed Lua object over the raw pointer handle.
-- Named fields read/write as plain Lua numbers; the author never sees an
-- offset, a width, or p:w32. Only `copper`, `experience` and `save` are
-- exposed; a typo on any other key errors rather than silently reading
-- garbage. Assigning an out-of-range value throws (record write refuses),
-- which is why scripts validate before assigning.
local function make_record(handle, chan)
  local proxy = {}
  return setmetatable(proxy, {
    __index = function(_, key)
      if key == "copper" then
        return handle:u32(OFF.copper)
      elseif key == "experience" then
        return handle:u32(OFF.exp_bil) * BILLION + handle:u32(OFF.exp_mod)
      elseif key == "save" then
        return function() M.save_player(chan) end
      end
      error("player record has no field " .. tostring(key))
    end,
    __newindex = function(_, key, v)
      if key == "copper" then
        handle:w32(OFF.copper, v)
      elseif key == "experience" then
        handle:w32(OFF.exp_raw, v)
        handle:w32(OFF.exp_mod, v % BILLION)
        handle:w32(OFF.exp_bil, v // BILLION)
      else
        error("player record has no writable field " .. tostring(key))
      end
    end,
  })
end

-- The caller's own record, or nil. `_GET_PLAYER` never returns null for an
-- in-range channel (every channel has a slot), so the module's own gate is
-- the loaded-flag byte; a command typed at the login prompt or on an empty
-- channel has no character to act on.
function M.player(c)
  local handle = M.get_player(c.chan)
  if handle == nil or handle:u8(OFF.loaded) == 0 then
    return nil
  end
  return make_record(handle, c.chan)
end

-- Look an item up by name, hiding the OUT-param cell. Returns the item
-- handle (or nil) and the match count. A NUL or over-long name is refused
-- here so the str marshaller never throws; it reads back as (nil, 0). PE32
-- stores the count as a dword, so the cell is 4 bytes and read as u32 (the
-- 16-bit word lands in the low half of the zeroed cell).
function M.find_item(c, name)
  if string.find(name, "\0", 1, true) or #name > 100 then
    return nil, 0
  end
  local cell = c:buffer(4)
  local item = M.get_item_from_name(name, nil, cell)
  return item, cell:u32(0)
end

return M
