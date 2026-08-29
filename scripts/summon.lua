-- Summon an item into the caller's inventory by name. Acquisition is not
-- level-gated (that check is at wear/wield time); encumbrance and a free
-- slot are enforced by _ADD_ITEM_TO_INVENTORY, whose bool return this reads.
--
-- An over-long or NUL-embedded name is refused here, before ever calling
-- `mud.find_item` (whose own refusal is indistinguishable from "no such
-- item" -- it exists so the str marshaller never throws, not to report a
-- reason to the player).
local mud = wccmmud

mmud.command("summon", function(c)
  local name = c.args
  if name == "" then
    c:print("summon what?\r\n")
    return mmud.HANDLED
  end
  if string.find(name, "\0", 1, true) or #name > 100 then
    c:print("not a valid item name.\r\n")
    return mmud.HANDLED
  end
  local item, count = mud.find_item(c, name)
  if not item then
    -- A null return with a nonzero count means the module already printed
    -- its own disambiguation prompt; say nothing more.
    if count ~= 0 then return mmud.HANDLED end
    c:print("no such item.\r\n")
    return mmud.HANDLED
  end
  if not mud.add_item(c.chan, item) then
    c:print("too heavy, or no room in your inventory.\r\n")
  end
  return mmud.HANDLED
end)
