-- Grant or take away coin. `cash <n>` adjusts the caller's own purse by n
-- COPPER (the smallest denomination). There is no need to pick a bigger
-- denomination for a large grant: coin weight tracks coin COUNT, not coin
-- VALUE, and the game's own currency-cleanup routine mints from the copper
-- accumulator highest-denomination-first -- so it already produces the
-- minimum-coin-count, and therefore minimum-weight, representation. Granting
-- copper and letting it normalise is both the game's own path and the light
-- one.
mmud.command("cash", function(c)
  local n = tonumber(c.args)
  if not n then
    c:print("cash <copper>\r\n")
    return mmud.HANDLED
  end
  local ok, reason = c:adjust_wealth(n)
  if ok then
    c:print("done.\r\n")
  else
    c:print(reason .. ".\r\n")
  end
  return mmud.HANDLED
end)
