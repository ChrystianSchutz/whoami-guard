# egress-guard

A PreToolUse hook for **Claude Code** and **Codex** (plus a curl/wget PATH shim for any agent) that stops a coding
agent from sending **your own identity** (account e-mail, name) to outside services.

The failure it targets is mundane: a site answers `403` and asks automated clients to declare a contact
("User-Agent: Sample Company AdminContact@..."), and the agent helpfully fills in the e-mail it has in its context,
for example `curl -A "filings-fetch/1.0 (you@your-mail.com)"`, or writes it into a script that will run every night.
Several public Claude Code issues report exactly this (anthropics/claude-code #95258, #98584, #102577, #104774).

Write-up with the full measurement: https://chrystianschutz.com/blog/TODO-SLUG

## What it does

- Knows *whose* data to protect. Generic PII detectors flag every e-mail address; egress-guard flags yours and lets
  others through (the site's own sample contact, other people's addresses, a `git config` that stays local).
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

The package is not on PyPI yet (the name `egress-guard` on PyPI belongs to an **unrelated project**: do not
`pip install egress-guard`). Install from source:

```sh
pipx install git+https://github.com/ChrystianSchutz/egress-guard
# or, into a venv you control:
python -m venv ~/.egress-guard/venv && ~/.egress-guard/venv/bin/pip install git+https://github.com/ChrystianSchutz/egress-guard
```

Both give you an `egress-guard-hook` command (and `egress-guard-shim`). Use that command, or the venv's own
interpreter, in the hook settings below.

**About `python -I`.** Isolated mode is a good default for hooks (no `PYTHONPATH`, no current directory on
`sys.path`), but it also ignores the **user site-packages**. A `pip install --user` copy is invisible to
`python -I -m egress_guard.hook`, and the hook then fails. Either install into the interpreter you call (a venv or
pipx, as above), or use the launcher in [`contrib/run_hook.py`](contrib/run_hook.py): copy it to
`~/.egress-guard/run_hook.py`, copy `src/egress_guard/` to `~/.egress-guard/pkg/egress_guard/`, and run
`python -I ~/.egress-guard/run_hook.py` (absolute path on Windows). That also pins the version the hook runs.

Check the install with one allowed and one denied event (the second line must print a `deny` decision):

```sh
echo '{"tool_name":"Bash","tool_input":{"command":"curl -A research-script/1.0 https://example.org"}}' | egress-guard-hook
echo '{"tool_name":"Bash","tool_input":{"command":"curl -A \"bot (you@your-mail.com)\" https://example.org"}}' | egress-guard-hook
```

(Put `you@your-mail.com` in `identity.json` first, see below.)

### Claude Code (`~/.claude/settings.json`)

```json
{"hooks": {"PreToolUse": [{"matcher": "Bash|PowerShell|WebFetch|Write|Edit|MultiEdit|mcp__.*",
  "hooks": [{"type": "command", "command": "egress-guard-hook", "onFailure": "block", "timeout": 10}]}]}}
```

Set `"onFailure": "block"`: hooks fail open by default, so a broken install would silently let everything through.
For lower latency there is a resident HTTP mode (`egress-guard-hook --serve 127.0.0.1:8977`, ~1 ms per call, no
process start); point a Claude Code HTTP hook at it.

### Codex (`~/.codex/config.toml`)

```toml
[[hooks.PreToolUse]]
matcher = "^(Bash|exec_command|shell|apply_patch|mcp__.*)$"
[[hooks.PreToolUse.hooks]]
type = "command"
command = "egress-guard-hook"
```

Codex asks you to review and trust the hook once.

### curl/wget shim (any agent, scripts the agent wrote)

Put a `curl` launcher earlier on `PATH` than the real one and set `EGRESS_GUARD_SHIM_DIR` to its folder:

```sh
# curl (sh)
exec egress-guard-shim curl "$@"
```

```bat
@rem curl.cmd
@egress-guard-shim curl %*
```

The shim also reads request bodies and headers given as files (`-d @body.json`, `-H @headers.txt`, `-K config`).

## Identity: `~/.egress-guard/identity.json`

```json
{"emails": ["you@your-mail.com"], "names": ["First Last"], "extra": ["+48 600 000 000"],
 "allow_hosts": ["github.com"], "ignore": ["firstlast-blog"], "strict": false, "autodetect": true}
```

- `emails`, `names`: what to protect. `extra`: any other string, matched verbatim (phone, handle).
- `allow_hosts`: destinations where your identity may go (for example your git host).
- `ignore`: strings cut out of a tool call (case-insensitive) before matching, for harmless text that contains your
  name, such as a project folder named after you (`cd ~/work/firstlast-blog && npm install`). Your identity elsewhere
  in the same call is still caught. Keep entries specific: anything listed here is never inspected.
- `strict`: scan every tool call, not only those that can reach the network.
- `autodetect` (default on): also adds `git config --global user.email` / `user.name`, the Claude Code account
  e-mail from `~/.claude.json`, a "First Last" spelled by a `first.last@` address, and a git `user.name` that carries
  a machine label (for example "Jan Desktop") verbatim. Placeholder addresses (`you@example.com`, GitHub noreply) are
  skipped. Everything is read locally, cached for a day in `~/.egress-guard/`, and never sent anywhere.
- `EGRESS_GUARD_HOME` moves the whole folder (identity, cache, log).

## Known gaps and limits

- **It checks tool calls; it is not network isolation.** A hook sees only what a tool call contains. A script that
  reads your e-mail at run time (from git config, an environment variable, a file) and sends it with a library call
  is outside its view. The shim covers the part of this that goes through curl/wget. In our reproduction the leaks
  came from scripts the agent wrote, which is why `Write|Edit` belong in the matcher.
- Codex hosted tools (web search) do not pass through hooks.
- Hooks fail open by default in both agents (see `onFailure` above for Claude Code).
- A request to your own personal domain that contains your surname (`curl https://kowalczyk-studio.pl`) is flagged:
  these are the 2 false alarms on the benchmark's test split. Add the domain to `allow_hosts`.
- Name matching covers English and Polish inflection; other inflected languages are not tested.
- Our numbers come from one machine, one Claude Code version, a mock site and synthetic identities. The held-out set
  is not adversarial. Treat egress-guard as a seatbelt, not a guarantee.

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
  title  = {egress-guard: an identity-aware egress hook for coding agents},
  year   = {2026},
  version = {0.1.0},
  url    = {https://github.com/ChrystianSchutz/egress-guard}
}
```

## Licence

MIT, see [LICENSE](LICENSE).
