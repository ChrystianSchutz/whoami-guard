# Changelog

## 0.2.4 (2026-11-24)

**No AI co-author in your commits.** A shell `git commit` (also `--amend`, `commit-tree`, `tag`, `merge`, `am`,
`cherry-pick`, `rebase`, `revert`, `notes`) whose message names an AI agent in a `Co-authored-by:` trailer, or
that sets an AI vendor address or name as author or committer, is denied with a message that says what to remove.
A `-F` / `--file` message file is read (64 KB). It does not depend on session exceptions (`--off` included); the
variable `EGRESS_GUARD_AI_AUTHOR` set to `allow` in the user's environment turns it off. Why: Google's CLA bot
failed a pull request on a `Co-authored-by: Claude <noreply@anthropic.com>` trailer after the human author had
signed.

**Approval memory: a question you approved is not asked again** in the same session for the same data in the same
kind of call (Claude Code). Before, a session with an `--ask` exception asked again on every call that named, for
example, your GitHub login in `gh pr create --head <login>:branch`, a minute after you approved the same.

- Register the hook for **PostToolUse** too (same command and matcher, see the README). Claude Code sends that
  event only for a call that really ran; when it is the very call the hook asked about (same session, same
  tool_use_id, same content), its findings become approvals. Without the PostToolUse entry nothing changes.
- An approval is keyed by the finding kind, the matched value and the call shape. MCP tools, web fetches and file
  tools: the whole tool input word for word (another channel, recipient, URL or file asks again). Shell: only a
  plain `gh` built-in command (`pr`, `issue`, `api`, `repo`, `gist`, `release`, `search`, `label`, `workflow`, `run`,
  `discussion`, `project`), bound to that command group, the folder it runs in and the host gh will talk to
  (`--hostname`, the HOST of `-R HOST/OWNER/REPO`, else a `GH_HOST` / `GH_REPO` the hook can see, else github.com;
  a URL in `--body` is not a target). A shell line with anything that can change the target at run time (`$`,
  backticks, redirections, pipes, chaining, globs, escapes, a bare `@file`, a whole URL as an argument, `-R` hidden
  in a bundle of short flags), a gh alias or extension, and every other command, curl included, is never
  remembered. gh options that read a file (`--body-file`, `-F`, `--input`) can change the content and, for
  `gh api graphql --input`, the repository on the same host, but not the host, so they are remembered. gh refuses
  aliases named like a built-in command, so `gh pr` is always gh's own. `GH_HOST` exported inside the agent's own
  shell is not visible to the hook (known limit).
- Only questions are remembered. A blocked call never runs, so a block never becomes an approval; exact matches
  that were a question only because of an `--ask` exception count only while that exception runs.
- Approvals end with the session exception (without one: after 2 hours) and with `whoami-guard-allow --clear`;
  `--list` shows how many each session has. `--clear` writes a new revocation epoch into `sessions.json` (only
  `whoami-guard-allow` writes that file), so approvals and open questions from before it count for nothing, also
  ones a call still finishing writes back after the delete, and a question asked across the clear (the hook reads
  the epoch once per decision). `whoami-guard-allow` changes `sessions.json` under a lock file
  (`sessions.lock`, left-over locks expire after 30 s), so an exception command running next to `--clear` cannot
  write old exceptions back; a locked or unwritable file is reported with exit 1, nothing changed. It says so when
  it cannot delete the approvals file (revoked anyway). An unreadable `sessions.json` fails closed: no approval
  counts until the next `whoami-guard-allow` writes a new epoch.
- A convenience against repeat prompts, not an authentication of your answer: approvals live in `approvals.json` in
  the whoami-guard folder as HMACs, never values, but the salt is in the same file, so an agent set on getting
  around the guard can forge one (same limits as the rest of the self-protection). A malformed file grants nothing
  and is replaced.
- A malformed, deeply nested `sessions.json` no longer crashes the hook (it grants nothing).
- Nothing is remembered in `bypassPermissions` / `dontAsk` mode (no question is shown there), under Codex (no
  questions) or in the HTTP mode (any local process could post a fake PostToolUse to the port).
- Self-protection: agent shell commands that run the hook itself (`whoami-guard-hook`, `python -m
  egress_guard.hook`, `run_hook.py`, `from egress_guard import hook`) are denied, so an agent cannot pipe a fake
  PostToolUse event into it. Reading those files still passes.

## 0.2.3 (2026-11-09)

**The approval command in block messages works as printed**, whatever the user's PATH:

- It is `<python> <package>/egress_guard/allow.py ...`: the Python and the package that run the hook, with full
  paths, so it works for uv tool, pipx, venv, uvx and `contrib/run_hook.py` installs alike. The bare
  `whoami-guard-allow` was "command not found" when the user's shell had another PATH than the agent (always for a
  `run_hook.py` install, which puts no command on PATH). `allow.py` now runs as a file.
- It is quoted for POSIX shells (Claude Code's `!` runs bash, also Git Bash on Windows; bash/zsh on macOS and
  Linux); on Windows the message adds a PowerShell form with `&`.
- It suggests the exception that really unblocks the call: `--host` for the sites in it (all of them, up to 12,
  leaving out allowed ones; it named only the first 3), `--email` only for someone else's address in a contact field
  (the user's own address and name have no allow list), `1 --ask` otherwise, and `1 --off` under Codex, which has
  no questions.
- Placeholders are `ID` / `ADDRESS`, not `<id>`, which bash reads as a redirect.
- `--list` also shows recent session ids, and a wrong `--session` lists them.
- `contrib/run_hook.py allow ...` runs the allow command from the pinned copy.

**Issue #1** (thanks to @mattabate): in the default mode `gh issue|pr|gist|release|repo|discussion|...` are
network commands like `gh api`, also with options before the subcommand (`gh --repo o/r issue create`), so an
e-mail or name in an issue body, PR comment or gist is checked. So are `npm|pnpm|yarn|bun|cargo publish`,
`docker|podman push`, `twine upload` and `gem push`, also as `npm.cmd`. The owner part of the parsed `-R` /
`--repo` argument of a gh command (the user's own GitHub account) does not count as a name; the posted text is
checked whole, also when it quotes a gh command.

**Fixes from the third Sol review** (gpt-6-sol, Not OK, 2 P1 + 4 P2, all confirmed):

- Self-protection compares the whoami-guard hook groups before and after a settings edit: narrowing the matcher,
  moving the hook to another event, `"disableAllHooks": true` or settings that no longer parse are denied, not only
  removing the hook's name. `$(whoami-guard-allow --off)`, backticks and `<( )` inside a reading command are denied.
- An allowed URL exempts a non-shell call only when the call's single destination is its `url`: WebFetch
  `{url, prompt}` or a browser navigate `{url}`. Evaluate calls, a `host` or `to` field beside the url and other
  shapes get the full scan. A file is exempt only when every URL, quoted host name and IP in it is allowed and it
  builds no other destination.
- A block without a session id prints `--session ID`, and `whoami-guard-allow` without `--session` refuses after
  such a block instead of picking the newest session.
- `"until": "nan"` / `inf` in `sessions.json` grants nothing (it granted `off` forever).
- Read / Glob / Grep of the whoami-guard folder pass; only writes are self-protection.

**Fixes from the Astra review of this release** (gpt-6-astra, round 4, Not OK, 6 P1 + 2 P2, all confirmed and
fixed before release): sed option forms (`--in-place`, `-e'...'`, options after operands, `w` / `e` commands),
`127.sink.test` and protocol-relative URLs passing as local, a quoted gh command in a posted body losing the name
check, MCP fields beside an allowed url, `package.json` scripts with curl, `gh --repo o/r issue create`,
PowerShell / metacharacter quoting of the approval command, and an exception Codex can use. Also: Codex
`config.toml` hook groups are compared parsed (a narrowed matcher line holds no "hook"), apply_patch denies any
changed hook or matcher line, and an 8 MB command of thousands of `;` segments is checked in about 2 s instead of
54 s (a hook past its timeout lets the call through).

**Round 5** (Not OK, 5 P1 + 1 P2, all confirmed and fixed): the local / allowed-host proof also reads hosts with a
trailing dot, Unicode and ideographic dots, numeric hosts and pieces glued by formatting (`'%s.test'`,
`f'{h}.test'`, `'sink' '.test'`, `.replace(..., '.')`, `chr`); the repo owner is cut only from shell commands and
never from an option's value (`--body -RJanKowalski/x`); inline code in data files counts (`node -e "fetch(...)"`
in package.json scripts, `python -c` in CI); gh / git / package commands are read token by token in one pass
(16,000 repeated `gh` took over 12 s, now milliseconds); apply_patch denies `*** Move to:` of the settings and moves
onto them; `--host` is suggested only when the scanner then lets the call through. `sed -n '/.egress-guard/p'` and
other print-only sed scripts pass.

**Round 6** (Not OK, 5 P1 + 1 P2, all confirmed and fixed): numeric hosts in every inet_aton form (`'8.8'`,
`'0x8.0x8.0x8.0x8'`, `'134744072'`) and hosts ended by an escape (`'sink.test\n'.strip()`) get no local exemption;
boolean gh flags (`--draft`, `--web`, `--comments`) take no value, so `--draft --body -RJanKowalski/x` keeps the
name check and `gh pr view --comments -R <you>/repo` passes; data files count imported calls
(`from requests import post`), interpreter heredocs (`python <<'PY'`) and commands inside JSON strings
(`"postinstall": "gh issue create ..."`); deeply nested settings deny instead of crashing the hook, and any scanner
error denies the call; the URL, sed and spelled-out `at` / `dot` patterns stay linear on adversarial 50 KB inputs
(they took 5-34 s; the last two also in 0.2.2).

**Fewer false blocks** (all seen in one working day):

- Data files (`.yaml .yml .json .toml .ini .cfg .xml`) count as outbound only when they hold a User-Agent or a
  command that sends (curl, gh, git push, publish ...): a CV in YAML listing "WebSocket, gRPC" among skills was
  blocked.
- Code whose only destinations are this machine (`localhost`, loopback IPs) and that builds no other one is local:
  a PDF generator opening `http://localhost:4173` was blocked.
- `sed` that only reads, and `sed -i` on a file that is not a control (a plain `s` script that merely mentions the
  whoami-guard folder) pass; the agent may run `whoami-guard-allow --list` / `--help`.

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

## 0.2.4 follow-up: owner-run control approvals

Block messages tell the agent to paste the exact owner-run command into the conversation. Self-protection now supports `--control-once DIGEST --session ID`: one unchanged operation, one session, ten minutes, without disabling other checks. See [details](docs/control-once.md).
