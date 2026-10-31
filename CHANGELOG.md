# Changelog

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
