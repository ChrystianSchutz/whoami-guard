# Exact control approval review — 2026-11-17

Reviewer: gpt-6-sol (high), independent static review.

Scope: control.py and hook.py/allow.py changes against the existing 0.2.4 working tree. No concrete correctness or security findings. Digest binds tool, full input and cwd; session is bound by the record key. Consume/grant/clear serialize through sessions.lock. Consumption precedes execution; TTL and epoch are checked. Other checks still run. Printed command appears executable. Referenced file contents remain outside digest scope.

Implementing agent validation: 205 tests passed, including the printed command executed in a child process against a temporary synthetic home, wrong session/cwd/input, replay, expiration, clear, malformed/unwritable stores and parallel consumption. One pre-existing invalid-escape warning.

VERDICT: OK for reviewed scope.
