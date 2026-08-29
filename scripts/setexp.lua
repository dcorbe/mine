-- NAMED `setexp`, NOT `exp`, DELIBERATELY.
--
-- `exp` is the player's natural abbreviation for MajorMUD's own `experience`
-- command (`cmd_experience`, ordinal 469), which SHOWS your experience. The
-- seam runs before the module, so registering `exp` here silently stole a
-- built-in every player uses -- typing `exp` to check your total got this
-- script's usage message instead. Found on a live board, 2026-08-20.
--
-- Command names shadow whatever the player would otherwise have typed, and
-- the seam has no channel-state scoping, so the shadow reaches the login
-- prompt too. Before naming a command, check it against the module's own:
--     python3 re/ne_exports.py re/WCCMMUD.DLL --list | grep cmd_
-- and make sure the name is not a built-in, nor a PREFIX of one -- MajorMUD
-- resolves abbreviations, so a short name captures every command it prefixes.
--
-- Set the caller's own total experience OUTRIGHT -- this overwrites the
-- total, it does not add to it (see `scripts/lib/wccmmud.lua`'s own record
-- object doc comment for why experience is stored THREE times and all three
-- copies must always agree).
local mud = wccmmud

local function whole_u32(n)
  if type(n) ~= "number" or n ~= n or n == math.huge or n == -math.huge or n % 1 ~= 0 then
    return nil, "amount must be a whole number"
  end
  if n < 0 then return nil, "amount must not be negative" end
  if n > 0xffffffff then return nil, "amount is too large" end
  return math.floor(n)
end

mmud.command("setexp", function(c)
  local raw = tonumber(c.args)
  if not raw then c:print("setexp <total>\r\n"); return mmud.HANDLED end
  local total, reason = whole_u32(raw)
  if not total then c:print(reason .. ".\r\n"); return mmud.HANDLED end
  local p = mud.player(c)
  if not p then c:print("no character loaded on this channel.\r\n"); return mmud.HANDLED end
  p.experience = total
  p:save()
  c:print("done.\r\n")
  return mmud.HANDLED
end)
