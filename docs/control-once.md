# Owner-run control approvals

The hook now tells the agent to paste the exact approval command into the conversation,
including the `!` prefix and full executable/package paths. A spoken or typed "yes" does
not grant an exception. The agent must wait for the owner to execute the command.

Self-protection denials offer `--control-once DIGEST --session ID`. This approves one
unchanged tool invocation, bound to its tool name, all input arguments, working directory,
and session. It expires after ten minutes. Consumption is locked and persisted before the
operation is admitted. A different command, directory, or session remains blocked.
Ordinary identity checks and AI-author checks still run. `--off` does not grant control
permissions; `--clear` revokes unused control approvals through the existing epoch.

Only the owner runs approval commands. The hook continues to deny agent attempts to run
them. This is a local convenience boundary, not a hostile-agent sandbox. Approval binds
arguments, not contents of referenced files: the owner must review scripts and patches
before approving a command that executes them. At most one pending grant per session is
kept; granting a new one replaces the old one.

The source and installed package are updated by `install_update.py`, run by the owner.
It checks all original and replacement hashes before touching files, saves original bytes,
and restores completed writes if a later write fails. The hook registration and existing
identity, exception, and approval stores are not changed. The same behavior instruction
is appended to the owner's Codex and Claude global instruction files.

## Agent-specific handoff wording

Codex must relay the exception command before further tools and treat a successful user shell result as execution confirmation, without waiting for another 'done'. Claude receives only a brief suggestion to paste the exception command. This follow-up changes message text and instructions only; permission checks are unchanged. Validation: 24 focused tests passed.
