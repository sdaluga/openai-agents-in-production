# Example 01 — What the SDK does before you configure it

```bash
python examples/01-audit-your-defaults/audit_defaults.py
```

No API key. No network. Under a second.

Three configurations go through the egress audit. **The middle one is the
point.**

| | | |
|---|---|---|
| 1 · `RunConfig()` | the quickstart | 2 blocking |
| 2 · the one that looks handled | logging flags set, workflow named | **2 blocking** |
| 3 · hardened | processor you own, no payloads | clean |

Configuration 2 is not careless. Somebody set `DONT_LOG_MODEL_DATA`, named
the workflow so traces would be attributable, and grouped them by tenant.
Every one of those was the right call.

It exports the same prompts as configuration 1.

`DONT_LOG_MODEL_DATA` governs the SDK's Python logger. The trace exporter is
a different code path with a different switch — and the one that is strict
by default is the one on data that never leaves the process.

## It checks itself

The script asserts its own premise before exiting: that 1 and 2 are blocked,
that 3 is clean, and that the log/trace inversion finding still fires. If a
future SDK release makes the defaults safe, it exits non-zero rather than
printing a reassuring table nobody re-reads.

**Read next:** [docs/01 · What the defaults do](../../docs/01-what-the-defaults-do.md)
