-- Set the caller's own total experience OUTRIGHT -- this overwrites the
-- total, it does not add to it (see c:set_exp's own doc comment, and the
-- doc comment on the Rust CommandCtx::set_experience it delegates to, for
-- why the record stores experience TWICE and both copies must always agree).
mmud.command("exp", function(c)
  local n = tonumber(c.args)
  if not n then
    c:print("exp <total>\r\n")
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
