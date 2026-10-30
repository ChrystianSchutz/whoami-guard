# Changelog

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
