"""Owner-issued, one-use approvals for an exact self-protection operation.

This is the same local trust boundary as sessions.json, not a sandbox. An approval
binds tool arguments and cwd, not the future contents of files a command may read.
"""
import hashlib
import json
import os
import re
import secrets
import time

FILE = "control-once.json"
TTL = 600


def digest(event):
    payload = [event.get("tool_name"), event.get("tool_input"), event.get("cwd")]
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()


def _read(home):
    try:
        value = json.loads((home / FILE).read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError, RecursionError):
        return {}


def _write(home, value):
    tmp = home / (FILE + "." + secrets.token_hex(8) + ".tmp")
    try:
        tmp.write_text(json.dumps(value), encoding="utf-8")
        os.replace(tmp, home / FILE)
    finally:
        tmp.unlink(missing_ok=True)


def grant(home, sid, key, epoch):
    """Called only by the owner's allow CLI, with the sessions lock held."""
    if not re.fullmatch(r"[a-f0-9]{64}", key):
        raise ValueError("--control-once requires the exact 64-character digest from the block message")
    data = _read(home)
    data[sid] = {"digest": key, "until": time.time() + TTL, "epoch": epoch}
    _write(home, data)


def consume(event, home):
    """Consume atomically before permitting the operation; errors always deny."""
    from egress_guard import allow, hook

    sid = str(event.get("session_id") or "")
    if not sid or not (home / FILE).exists():
        return False
    lock = allow._lock(home)
    if lock is None:
        return False
    try:
        data = _read(home)
        rec = data.get(sid)
        epoch = hook._epoch()
        if not isinstance(rec, dict) or epoch == hook.EPOCH_BROKEN:
            return False
        if (rec.get("digest") != digest(event) or rec.get("epoch") != epoch
                or not time.time() < hook._num(rec.get("until")) <= time.time() + TTL):
            return False
        del data[sid]
        _write(home, data)
        return True
    except (OSError, ValueError, TypeError):
        return False
    finally:
        try:
            lock.unlink(missing_ok=True)
        except OSError:
            pass
