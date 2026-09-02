#!/usr/bin/env python3
"""
Example 01 — what the SDK does before you configure it.

    python examples/01-audit-your-defaults/audit_defaults.py

No API key. No network. Under a second.

This runs the egress audit against three configurations: the one you get by
writing `RunConfig()`, the one most teams reach for first, and a hardened
one. The middle column is the interesting one — it is the configuration of
somebody who thought about this and still ships prompts to a third party.

The script asserts its own premise before exiting. If a future SDK release
makes the default configuration safe, this stops demonstrating anything and
exits non-zero rather than printing a reassuring table nobody re-reads.
"""

from __future__ import annotations

try:
    from agents import ModelSettings, RunConfig
except ImportError:  # pragma: no cover
    print("This example needs the SDK:  pip install 'agent-service[sdk]'")
    # `from None`: the ImportError traceback is noise for somebody who
    # just needs the pip command.
    raise SystemExit(1) from None

from agent_service.posture import audit, render

# An environment with nothing set — the common case, and the one the SDK's
# own defaults govern. Passed explicitly so this example produces the same
# output on a laptop that happens to have OPENAI_AGENTS_* exported.
CLEAN_ENV: dict[str, str] = {}

BAR = "─" * 74


def show(title: str, note: str, **audit_kwargs) -> object:
    posture = audit(**audit_kwargs)
    print(f"\n{BAR}\n  {title}\n  {note}\n{BAR}\n")
    print(render(posture))
    verdict = "RELEASABLE" if posture.is_releasable else "BLOCKED"
    print(
        f"  → {verdict}  "
        f"({len(posture.blocking)} blocking, {len(posture.warnings)} warnings)"
    )
    return posture


def main() -> int:
    print("\n" + "=" * 74)
    print("  Egress posture — three configurations")
    print("=" * 74)

    # ------------------------------------------------------------------ 1
    default = show(
        "1 · RunConfig()",
        "What you get from the quickstart.",
        run_config=RunConfig(),
        model_settings=ModelSettings(),
        environ=CLEAN_ENV,
        tenant_id="acme",
    )

    # ------------------------------------------------------------------ 2
    # The configuration of somebody who read one page of the docs, set the
    # logging flags, named their workflow, and stopped. Everything they did
    # was correct. None of it touched the export.
    thoughtful = show(
        "2 · The one that looks handled",
        "Logging flags set, workflow named — and every prompt still exported.",
        run_config=RunConfig(workflow_name="inbox-triage", group_id="tenant:acme"),
        model_settings=ModelSettings(),
        environ={
            "OPENAI_AGENTS_DONT_LOG_MODEL_DATA": "true",
            "OPENAI_AGENTS_DONT_LOG_TOOL_DATA": "true",
        },
        tenant_id="acme",
    )

    # ------------------------------------------------------------------ 3
    hardened = show(
        "3 · Hardened",
        "Tracing kept, but to a processor you own, without payloads.",
        run_config=RunConfig(
            workflow_name="inbox-triage",
            group_id="tenant:acme",
            trace_include_sensitive_data=False,
        ),
        model_settings=ModelSettings(store=False),
        environ=CLEAN_ENV,
        trace_processors=[object()],  # stand-in for EstateTraceProcessor
        tenant_id="acme",
    )

    # ------------------------------------------------------------------
    print("\n" + "=" * 74)
    print("  The middle column is the point")
    print("=" * 74)
    print(
        """
  Configuration 2 is not careless. Somebody set the logging flags, named
  the workflow so traces would be attributable, and grouped them by tenant.
  Every one of those was the right call.

  It exports the same prompts as configuration 1.

  DONT_LOG_MODEL_DATA governs the SDK's Python logger. The trace exporter
  is a different code path with a different switch, and the one that is
  strict by default is the one on data that never leaves the process.
"""
    )

    # -- assert the demonstration still demonstrates ---------------------
    problems: list[str] = []
    if default.is_releasable:
        problems.append("A bare RunConfig() now passes the audit.")
    if thoughtful.is_releasable:
        problems.append(
            "Configuration 2 now passes, so the point about the logging "
            "flags no longer lands."
        )
    if not hardened.is_releasable:
        problems.append(
            "The hardened configuration no longer passes. A gate nobody can "
            "satisfy is a gate that gets bypassed — fix the audit, not the "
            "config."
        )
    if thoughtful.by_code("posture:log-trace-inversion") is None:
        problems.append("The log/trace inversion finding stopped firing.")

    if problems:
        print("  THIS EXAMPLE HAS STOPPED DEMONSTRATING ITS POINT:\n")
        for p in problems:
            print(f"    - {p}")
        return 1

    print("  premise verified: 1 and 2 blocked, 3 clean.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
