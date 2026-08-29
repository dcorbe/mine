-- Grant or take away coin. `cash <n>` adjusts the caller's own purse by n
-- COPPER. Non-negative grants (poke the copper accumulator, let the game's
-- own cleanup mint it into denominations, save); negative deducts via the
-- module's own wealth export, which refuses if unaffordable and saves
-- itself. Validation lives here: an out-of-range value assigned to
-- p.copper would throw and disable the command, so it is refused first with
-- the same honest reasons the old lib gave.
local mud = wccmmud

local function whole_u32(n)
  if type(n) ~= "number" or n ~= n or n == math.huge or n == -math.huge or n % 1 ~= 0 then
    return nil, "amount must be a whole number"
  end
  if n < 0 then return nil, "amount must not be negative" end
  if n > 0xffffffff then return nil, "amount is too large" end
  return math.floor(n)
end

mmud.command("cash", function(c)
  local raw = tonumber(c.args)
  if not raw then
    c:print("cash <copper>\r\n")
    return mmud.HANDLED
  end

  if raw < 0 then
    local amount, reason = whole_u32(-raw)
    if not amount then c:print(reason .. ".\r\n"); return mmud.HANDLED end
    if mud.addon_adjust_user_wealth(c.chan, amount) then
      c:print("done.\r\n")
    else
      c:print("insufficient funds.\r\n")
    end
    return mmud.HANDLED
  end

  local amount, reason = whole_u32(raw)
  if not amount then c:print(reason .. ".\r\n"); return mmud.HANDLED end
  local p = mud.player(c)
  if not p then c:print("no character loaded on this channel.\r\n"); return mmud.HANDLED end
  p.copper = (p.copper + amount) & 0xffffffff
  mud.cleanup_currency(c.chan)
  p:save()
  c:print("done.\r\n")
  return mmud.HANDLED
end)
