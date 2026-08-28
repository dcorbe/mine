-- Grant or take away coin. `cash <n>` adjusts the caller's own purse by n
-- COPPER (the smallest denomination). There is no need to pick a bigger
-- denomination for a large grant: coin weight tracks coin COUNT, not coin
-- VALUE, and the game's own currency-cleanup routine mints from the copper
-- accumulator highest-denomination-first -- so it already produces the
-- minimum-coin-count, and therefore minimum-weight, representation. Granting
-- copper and letting it normalise is both the game's own path and the light
-- one.
--
-- A non-negative amount grants (`M.grant_copper`); a negative one deducts
-- the same magnitude (`M.deduct_wealth`) -- asymmetric on purpose, since the
-- module itself has no single export that credits a player (see
-- `scripts/lib/wccmmud.lua`'s own doc comment on `M.deduct_wealth` for why).
-- Validation (whole number, non-negative magnitude, fits 32 bits) lives in
-- the lib now, not here -- this script only picks which of the two lib
-- calls to make and prints whatever reason comes back.
local mud = wccmmud

mmud.command("cash", function(c)
  local n = tonumber(c.args)
  if not n then
    c:print("cash <copper>\r\n")
    return mmud.HANDLED
  end

  local ok, reason
  if n >= 0 then
    ok, reason = mud.grant_copper(c, n)
  else
    ok, reason = mud.deduct_wealth(c, -n)
  end

  if ok then
    c:print("done.\r\n")
  else
    c:print(reason .. ".\r\n")
  end
  return mmud.HANDLED
end)
