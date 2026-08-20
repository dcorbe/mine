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
-- total, it does not add to it (see c:set_exp's own doc comment, and the
-- doc comment on the Rust CommandCtx::set_experience it delegates to, for
-- why the record stores experience TWICE and both copies must always agree).
mmud.command("setexp", function(c)
  local n = tonumber(c.args)
  if not n then
    c:print("setexp <total>\r\n")
    return mmud.HANDLED
  end
  local ok, reason = c:set_exp(n)
  if ok then
    c:print("done.\r\n")
  else
    c:print(reason .. ".\r\n")
  end
  return mmud.HANDLED
end)
