-- Summon an item into the caller's inventory by name.
--
-- Acquisition is NOT level- or class-gated: `user_can_use`, where that
-- check lives, is only reached at wear/wield time (`wear_armour`,
-- `user_is_wearing`, `update_allowed_worn_items`), never here. A summoned
-- item lands in inventory regardless of level; the player just cannot
-- equip it. What IS enforced here is encumbrance -- `_ADD_ITEM_TO_INVENTORY`
-- refuses when the item would put the player over their weight cap, or
-- when there is no free inventory slot.
--
-- `mud.summon` answers three different ways, not one boolean, because the
-- three failures mean different things to the player: no such item exists,
-- several items matched and the module has ALREADY told the player so (in
-- which case this script must say nothing more), or the item was found but
-- would not fit. The recipe itself -- the six-word/three-far-pointer call
-- shape, the null-return disambiguation -- lives in `scripts/lib/wccmmud.lua`
-- now, not here; this script is just the player-facing wording.
local mud = wccmmud

mmud.command("summon", function(c)
  local name = c.args
  if name == "" then
    c:print("summon what?\r\n")
    return mmud.HANDLED
  end

  local ok, reason = mud.summon(c, name)
  if not ok then
    if reason == "ambiguous" then
      -- The module already prompted the player to narrow it down --
      -- saying anything more here would talk over that prompt.
    elseif reason == "no such item" then
      c:print("no such item.\r\n")
    elseif reason == "item name too long" or reason == "item name must not contain a NUL byte" then
      c:print("not a valid item name.\r\n")
    else
      c:print("too heavy, or no room in your inventory.\r\n")
    end
  end
  return mmud.HANDLED
end)
