# whoami-guard

A PreToolUse hook for **Claude Code** and **Codex** (plus a curl/wget PATH shim for any agent) that stops a coding
agent from sending **your own identity** (account e-mail, name) to outside services.

The failure it targets is mundane: a site answers `403` and asks automated clients to declare a contact
("User-Agent: Sample Company AdminContact@..."), and the agent helpfully fills in the e-mail it has in its context,
for example `curl -A "filings-fetch/1.0 (you@your-mail.com)"`, or writes it into a script that will run every night.
Several public Claude Code issues report exactly this (anthropics/claude-code #95258, #98584, #102577, #104774).

Write-up with the full measurement: https://chrystianschutz.com/blog/coding-agents-send-your-email/

## What it does

- Knows *whose* data to protect. Generic PII detectors flag every e-mail address; whoami-guard flags yours and lets
  others through (the site's own sample contact, other people's addresses, a `git config` that stays local).
  One conservative exception: your mailbox name alone (6+ characters, not just a first name) is protected too, so
  `yourname@other-domain` is blocked as well.
- Matches your e-mail and name in the forms we test: case, diacritics, URL and double URL encoding, HTML entities,
  base64 (also inside URL paths), `name at domain dot com`, separators, name order, Polish inflection.
- Looks only at tool calls that can reach the network (curl, wget, Invoke-WebRequest, Python/Node one-liners,
  WebFetch, MCP calls), at code the agent writes or edits when that code sends requests, and at the script behind
  `python fetch.py` when the agent runs one. Local commands (`git config user.email ...`, `echo ... >> AUTHORS`)
  are left alone, also when chained with an unrelated download.
- Pure standard library, no model, no dependencies; a scan takes well under 1 ms (p95 0.2-0.5 ms on our machine).
- Logs every decision to `~/.egress-guard/log.jsonl` with the matched *kind* (email, name, surname), never the value.

## Measured result

Coverage on our tests, not a guarantee. Details, commands and caveats: [docs/RESULTS.md](docs/RESULTS.md).

| test | result |
|---|---|
| Real Claude Code harness, mock site that asks for contact details, 60 interleaved baseline/guard pairs (Opus + Haiku, 3 tasks, 10 reps) | identity reached the site in **8/60** runs without the hook, **0/60** with it (exact McNemar p = 0.0078) |
| Independent held-out set written by another model family (120 cases, not adversarial) | 60/60 leaks caught, 0/60 false alarms (Wilson 95%: [0.94, 1.0] and [0, 0.06]) |
| Synthetic benchmark, test split (the scanner was tuned on this set: a regression guard, not an estimate) | 163/163 leaks caught, 2/150 false alarms |

All 8 baseline leaks came from Haiku; Opus leaked 0/30 with and without the hook. One machine, one Claude Code
version. Generic detectors (Presidio, GLiNER, plain regex) flag 60-85% of the hard negatives on the same benchmark,
because they cannot tell your address from anyone else's.

## Install

```sh
pipx install whoami-guard
# or, into a venv you control:
python -m venv ~/.egress-guard/venv && ~/.egress-guard/venv/bin/pip install whoami-guard
```

Both give you an `whoami-guard-hook` command (and `whoami-guard-shim`). Use that command, or the venv's own
interpreter, in the hook settings below.

**About `python -I`.** Isolated mode is a good default for hooks (no `PYTHONPATH`, no current directory on
`sys.path`), but it also ignores the **user site-packages**. A `pip install --user` copy is invisible to
`python -I -m egress_guard.hook`, and the hook then fails. Either install into the interpreter you call (a venv or
pipx, as above), or use the launcher in [`contrib/run_hook.py`](contrib/run_hook.py): copy it to
`~/.egress-guard/run_hook.py`, copy `src/egress_guard/` to `~/.egress-guard/pkg/egress_guard/`, and run
`python -I ~/.egress-guard/run_hook.py` (absolute path on Windows). That also pins the version the hook runs.

Check the install with one allowed and one denied event (the second line must print a `deny` decision):

```sh
echo '{"tool_name":"Bash","tool_input":{"command":"curl -A research-script/1.0 https://example.org"}}' | whoami-guard-hook
echo '{"tool_name":"Bash","tool_input":{"command":"curl -A \"bot (you@your-mail.com)\" https://example.org"}}' | whoami-guard-hook
```

(Put `you@your-mail.com` in `identity.json` first, see below.)

### Claude Code (`~/.claude/settings.json`)

```json
{"hooks": {"PreToolUse": [{"matcher": "Bash|PowerShell|WebFetch|Write|Edit|MultiEdit|mcp__.*",
  "hooks": [{"type": "command", "command": "whoami-guard-hook", "onFailure": "block", "timeout": 10}]}]}}
```

Set `"onFailure": "block"`: hooks fail open by default, so a broken install would silently let everything through.
For lower latency there is a resident HTTP mode (`whoami-guard-hook --serve 127.0.0.1:8977`, ~1 ms per call, no
process start); point a Claude Code HTTP hook at it.

### Codex (`~/.codex/config.toml`)

```toml
[[hooks.PreToolUse]]
matcher = "^(Bash|exec_command|shell|apply_patch|mcp__.*)$"
[[hooks.PreToolUse.hooks]]
type = "command"
command = "whoami-guard-hook --codex"   # Codex has no "ask": questions become blocks
```

Codex asks you to review and trust the hook once.

### curl/wget shim (any agent, scripts the agent wrote)

Put a `curl` launcher earlier on `PATH` than the real one and set `EGRESS_GUARD_SHIM_DIR` to its folder:

```sh
# curl (sh)
exec whoami-guard-shim curl "$@"
```

```bat
@rem curl.cmd
@whoami-guard-shim curl %*
```

The shim also reads request bodies and headers given as files (`-d @body.json`, `-H @headers.txt`, `-K config`).

## Identity: `~/.egress-guard/identity.json`

```json
{"emails": ["you@your-mail.com"], "names": ["First Last"], "extra": ["+48 600 000 000"],
 "allow_hosts": ["github.com"], "ignore": ["firstlast-blog"], "strict": false, "autodetect": true}
```

- `emails`, `names`: what to protect. `extra`: any other string, matched verbatim (phone, handle).
- `allow_hosts`: destinations where your identity may go (for example your git host). It applies to WebFetch
  and MCP calls only. Shell commands are always scanned: a shell line can name an allowed host and still send
  elsewhere (pipes, substitutions, git `host:path`). A `git push origin` names no identity and passes; a push to a
  URL that contains your name is blocked.
- `ignore`: strings cut out of a tool call (case-insensitive) before matching, for harmless text that contains your
  name, such as a project folder named after you (`cd ~/work/firstlast-blog && npm install`). Your identity elsewhere
  in the same call is still caught. Keep entries specific: anything listed here is never inspected. `ignore` only hides name matches inside one literal token (no spaces, `%` or encoded forms): your e-mail is always checked on the
  whole call, and an entry with spaces or one that is a piece of your name (`kowalski`, `Jan-Kowalski`) is dropped.
  Note that an agent that can write files could edit `identity.json`; protect it like other agent settings.
- `strict`: scan every tool call, not only those that can reach the network.
- `autodetect` (default on): also adds `git config --global user.email` / `user.name`, the Claude Code account
  e-mail from `~/.claude.json`, a "First Last" spelled by a `first.last@` address, and a git `user.name` that carries
  a machine label (for example "Jan Desktop") verbatim. Placeholder addresses (`you@example.com`, GitHub noreply) are
  skipped. Everything is read locally, cached for a day in `~/.egress-guard/`, and never sent anywhere.
- `EGRESS_GUARD_HOME` moves the whole folder (identity, cache, log).

### Allow lists, questions and session exceptions (0.2.x)

```json
{"emails": ["you@your-mail.com"], "names": ["First Last"],
 "allow_emails": ["agents@your-domain.com"],
 "allow_hosts": ["github.com", "wordpress.org"]}
```

- `allow_emails`: addresses agents may send anywhere without asking (User-Agent, From, forms). Never list your
  private address here. A block message names these addresses, so the agent can switch to one of them.
- `allow_hosts`: sites where your identity may go. WebFetch and MCP calls (browser navigation included) to them
  pass; a shell command to them **asks** instead of blocking, because a shell line can name an allowed host and send
  elsewhere.
- Exact matches of your identity are **denied**, in every tool the hook sees, browser MCP tools included (a browser
  `type` call carries no URL, so typing your private address into a form is denied: use an `allow_emails` address).
- Two checks **ask** (Claude Code shows a permission prompt) because they can be wrong:
  - `fuzzy` (`"ask"` default, `"deny"`, `"off"`): other ways to write the same thing, not encodings: Unicode
    look-alikes and zero-width characters (treated as exact and denied), German/Polish transliteration
    (Müller / Mueller, Schmidt / Szmit, Christian / Krystian), digits for letters (Mu11er), one or two typos, also
    in URL-decoded and base64 forms. Applies to `names`, `emails` and `extra`. "Anna Miller" when you are
    "Jan Miller" is someone else and passes.
  - `contact_fields` (`"ask"` default, `"deny"`, `"off"`): **any** e-mail address, not only yours, in a field whose
    job is to say who is calling: User-Agent (`-A`, `--user-agent`, `User-Agent:`), `From:`, `X-Contact`,
    `git -c user.email`, `email=` / `contact=` parameters. Sites such as SEC EDGAR ask for a contact in the
    User-Agent and an agent fills it with the address it knows: yours.
- `first_alone` (default `false`): also ask about your first name on its own (useful for a rare first name).
- **Escalation, without any server:** every block or question tells the agent to stop, tell you what it wants to
  send, where and why, and hand you the exact command that approves it for this session only, for example
  `! whoami-guard-allow --host data.sec.gov`.
- **Session exceptions** (`whoami-guard-allow`, run by you inside the agent session with the `!` prefix, which Claude
  Code runs outside the hooks): `--email ADDR` / `--host HOST` add to the allow lists for this session only;
  no list means questions instead of blocks; `--off` turns checks off; a number sets the hours (default 2);
  `--list`, `--clear`. "This session" is the session of the last tool call the hook saw; the command prints its
  folder. The hook denies agent tool calls that run this command, set `EGRESS_GUARD_*` variables or write into the
  whoami-guard folder, so an agent cannot grant itself an exception.
- Per terminal: `EGRESS_GUARD_MODE=ask` (questions instead of blocks) or `off`, set before starting the agent.
- **Codex** has no "ask": add `--codex` to the hook command there and every question becomes a block.

Measured: gate set recall 0.994 -> 0.997 with the same 3 false alarms as 0.1.1 (40 rows that put someone else's
address in a User-Agent now ask by design and are counted apart). Replaying the hooked tool calls (Bash, WebFetch,
Write, Edit, MCP) from the author's own Claude Code transcripts (73,967 tool calls in all): 4 fuzzy questions,
29 contact-field questions. Ciphers (rot13, hex, a custom code) are out of scope: a pattern matcher cannot stop an
agent that hides.

## Known gaps and limits

- **It checks tool calls; it is not network isolation.** A hook sees only what a tool call contains. A script that
  reads your e-mail at run time (from git config, an environment variable, a file) and sends it with a library call
  is outside its view. The shim covers the part of this that goes through curl/wget. In our reproduction the leaks
  came from scripts the agent wrote, which is why `Write|Edit` belong in the matcher.
- Codex hosted tools (web search) do not pass through hooks.
- **In the default mode, only commands the scanner recognises as network calls are checked** (curl, wget, HTTP
  libraries, sockets, remote git commands, ...). A network tool it does not list, or one under another name, is
  not scanned; set `"strict": true` to scan every call. A release review with Codex (9 rounds, 2026-10-30) found and
  closed a series of such forms (pipes, substitutions, git `host:path`, `git.exe`); expect more.
- The guard errs toward blocking: a local write next to a network command, or a file named `socket.log`, can be
  blocked although nothing is sent.
- Hooks fail open by default in both agents (see `onFailure` above for Claude Code).
- A request to your own personal domain that contains your surname (`curl https://kowalczyk-studio.pl`) is flagged:
  these are the 2 false alarms on the benchmark's test split. Add the domain to `allow_hosts` (fetches) or `ignore` (folder names).
- Name matching covers English and Polish inflection; other inflected languages are not tested.
- Our numbers come from one machine, one Claude Code version, a mock site and synthetic identities. The held-out set
  is not adversarial. Treat whoami-guard as a seatbelt, not a guarantee.

## Repository layout

| path | what |
|---|---|
| `src/egress_guard/` | `scan.py` (matcher), `hook.py` (command and HTTP hook), `shim.py` (curl/wget shim) |
| `tests/` | unit and end-to-end tests (`pytest`) |
| `bench/` | synthetic dataset and generator (`make_dataset.py`, seed 20261026), held-out set, gate bench (`run.py`, limits in `thresholds.json`), detector comparison (`bench_detectors.py`) |
| `repro/` | real-harness reproduction: mock site, sandbox hook, runner, scorer |
| `contrib/run_hook.py` | launcher for `python -I` with a pinned copy of the package |
| `docs/RESULTS.md` | numbers, commands, caveats |

All identities in `bench/` and `tests/` are invented. Reproduction runs (`repro/run_repro.py`) store the real
identity of whoever runs them under `runs/`, which is git-ignored; never commit it.

## Development

```sh
pip install -e . pytest ruff
ruff check .
pytest -q
python -I bench/run.py        # gate bench: recall >= 0.97, FPR <= 0.02, p95 <= 2 ms
python -I bench/heldout.py <tag>
```

## Citation

```bibtex
@software{schutz2026egressguard,
  author = {Schutz, Chrystian},
  title  = {whoami-guard: an identity-aware egress hook for coding agents},
  year   = {2026},
  version = {0.2.1},
  url    = {https://github.com/ChrystianSchutz/whoami-guard}
}
```

## Licence

MIT, see [LICENSE](LICENSE).
