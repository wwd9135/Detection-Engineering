# Tuning Index

Each entry here documents a discrete tuning change to an existing detection — before/after logic, the hypothesis that motivated the change, and the metrics proving it reduced noise without losing true positives.

See [docs/tuning-template.md](../docs/tuning-template.md) for the template.

---

## Tuning Records

| Date | Rule | Problem | Change | FP Rate Before | FP Rate After |
|---|---|---|---|---|---|
| 2026-06-14 | [T1547.001 Run Key](../detections/persistence/T1547.001-registry-run-keys/README.md) | msiexec writes noisy | Added msiexec filter | ~70% (synthetic baseline) | ~30% (estimated) |
| *(more to come)* | | | | | |

---

## Tuning Philosophy

See [docs/methodology.md](../docs/methodology.md) §5 for the full tuning workflow.

**Short version:**
- Deploy rules in observe mode first — don't tune against hypothetical FPs.
- Base every filter on observed data, not assumptions.
- Validate that each new filter does NOT suppress the emulated true positive.
- Document the before/after metrics so you can show the improvement was real.
- Prefer narrow filters (specific process paths, signed binary checks) over broad ones (entire directory trees, entire process names without path anchors).
