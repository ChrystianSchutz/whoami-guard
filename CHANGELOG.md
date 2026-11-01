# Changelog

## 0.2.2 (2026-11-01)

Fixes from the second Sol review (gpt-6.1-sol, Not OK, 6 findings, all confirmed):

- Session exceptions are bound to the session that asked: block messages carry `--session <id>`, and without it
  `whoami-guard-allow` refuses when several sessions were active in the last 10 minutes (an approval could reach
  another session).
- Self-protection covers quoted and full-path runs of the allow command, inline code that names the whoami-guard
  folder, writes to the agent's hook settings and edits or patches that drop the hook entry; it reads shell quotes
  and heredocs, so reading and documenting the controls still passes.
- An allowed host no longer exempts the whole MCP or fetch call: every destination in it counts, also URL-encoded
  redirect parameters and protocol-relative `//host` URLs; a backslash counts only in the host part (a `\n` after
  a URL in code was blocked).
- Malformed `sessions.json` records grant nothing and crash neither the hook nor `--clear`.
- `allow_emails` are compared as written: a Cyrillic look-alike of an approved address asks.
- Calls over 256 KB get exact checks only (an 8 MB call took 13 s, over the hook timeout).

## 0.2.1 (2026-11-01)

Fixes from the Sol review of 0.2.0 (gpt-6.1-sol, Not OK, 7 findings, all confirmed) and owner decisions:

- Browser MCP tools are scanned again like every other call (0.2.0 skipped them: an identity in a navigation URL
  passed, a regression). `allow_hosts` lets navigation to listed sites through.
- Codex: `--codex` turns every question into a block (Codex treats "ask" as unsupported and runs the tool).
- E-mail extraction is linear (a 100 KB malformed User-Agent took 54 s in 0.2.0, over the hook timeout).
- Header values are read up to the end of the quoted argument (`-H "User-Agent: bot x@y"`, `From: Name <x@y>`,
  `-Ax@y`, HTTPie); fuzzy checks also read URL-decoded and base64 views; short sound keys keep one typo for long
  names but never more typos than key letters beyond 3 (a replay found 3,848 false questions otherwise); digits
  for letters in e-mail addresses.
- `allow_emails` (was `contact_alias`, still read) matches exact addresses only; `noreply` only as a whole local
  part or the GitHub noreply domain.
- New: `allow_hosts` in shell commands asks instead of blocking; block messages name the approved addresses and the
  exact approval command; per-session exceptions (`whoami-guard-allow`) with self-protection; `EGRESS_GUARD_MODE`
  per terminal.

## 0.2.0 (2026-11-01)

- Fuzzy matching of the identity (`fuzzy`: ask / deny / off): Unicode look-alikes and zero-width characters (denied
  as exact), German/Polish transliteration, digits for letters, one or two typos; also for `extra` phrases.
- Contact-field rule (`contact_fields`: ask / deny / off): any e-mail address in User-Agent, From, X-Contact,
  git user.email or e-mail URL parameters asks first; `contact_alias` lists addresses agents may use there.
- Browser MCP tools (Playwright, Chrome) are not scanned unless `scan_browser` is set; page-script tools still are.
- The hook now returns `ask` for these findings and `deny` for exact ones.
- Not reviewed by a second model before release (owner's decision, 2026-11-01).

## 0.1.1 (2026-10-31)

Fixes from the final review of 0.1.0:

- `allow_hosts` (WebFetch/MCP) now reads the real host of each URL: a URL with userinfo
  (`https://trusted.test:pw@sink.test/`) is never treated as an allowed host.
- Shell commands are split at `&&`, `||`, `;` and newlines only outside quotes, so a quoted request body such as
  `curl ... -d 'x;git config user.email ...'` is still scanned.

## 0.1.0 (2026-10-30)

First public release.

Before release, 9 Codex review rounds closed: chained file uploads, socket one-liners, `ignore` entries that could hide
the identity (pieces, encoded forms, phrases), `allow_hosts` in shell commands (now WebFetch/MCP only), remote git
commands (`git ls-remote host:path`, `git://`, `git.exe`, global options).

- `egress_guard.hook`: PreToolUse hook for Claude Code and Codex (command mode; HTTP mode with `--serve`). Denies tool
  calls that would send the user's own e-mail or name off the machine, with a reason that tells the agent what to do
  instead. Console script `whoami-guard-hook`.
- `egress_guard.shim`: curl/wget PATH shim, also reads request bodies and headers given as files. Console script
  `whoami-guard-shim`.
- `egress_guard.scan`: identity-aware matcher (case, diacritics, URL/double URL encoding, HTML entities, base64 also in
  URL paths, `at`/`dot` spelling, separators, name order, Polish inflection); network gate for shell commands; scans
  code the agent writes when that code sends requests, and the script behind `python script.py`.
- Identity from `~/.egress-guard/identity.json` plus autodetection (git config, Claude Code account e-mail, a name
  spelled by a `first.last@` address, a git name with a machine label kept verbatim); placeholder addresses skipped;
  `ignore` list for harmless strings that contain the name (cut out before matching; entries that are or contain the protected identity are dropped).
- Decision log with the matched kind only, never the value.
- Synthetic benchmark (630 rows) with generator, independent held-out set (120 rows), gate thresholds, detector
  comparison script, and the real-harness reproduction (mock site, sandbox hook, runner, frozen-identity scorer).
