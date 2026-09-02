"""
Data-egress posture for an OpenAI Agents SDK run.

--------------------------------------------------------------------------
Why this module is first in the package
--------------------------------------------------------------------------
The Agents SDK is pleasant to start with and its defaults are tuned for that
first pleasant hour. Three of them move your data somewhere you did not
choose, and none of them announce it:

  1. `RunConfig.tracing_disabled` defaults to False. Tracing is ON.
  2. With no processor installed, the default exporter POSTs spans to
     https://api.openai.com/v1/traces/ingest using OPENAI_API_KEY.
  3. `RunConfig.trace_include_sensitive_data` defaults to True, so those
     spans carry model inputs, model outputs, and tool-call arguments.

Every one of those is verified against the installed package in
`tests/test_posture.py::TestTheDefaultsAreWhatWeSayTheyAre`, not asserted
from documentation. If a future SDK release changes one, that test fails and
this docstring is wrong — which is the point of writing it as a test.

There is a fourth fact that is easy to get backwards, so it has its own test:

  4. `OPENAI_AGENTS_DONT_LOG_MODEL_DATA` and `..._DONT_LOG_TOOL_DATA` default
     to **True**. Those govern the SDK's *local Python logging* only. They do
     not touch the trace export.

So the shipped posture is: local logs redacted, remote export verbose. That
inversion is the single most surprising thing in this repository, and it is
surprising in the expensive direction — the engineer reads "don't log model
data: true", concludes the SDK is careful, and never looks at the exporter.

None of this is a vulnerability and none of it is hidden; it is all in the
documentation for anyone who goes looking. The failure is that nobody goes
looking at defaults, because a default reads as a decision somebody already
made on your behalf. For a consumer prototype these are good defaults. For a
regulated workload they are a data-residency finding that lands in an
architecture review months after the code shipped.

--------------------------------------------------------------------------
What this module does NOT do
--------------------------------------------------------------------------
It does not make your deployment compliant, and it cannot see your
deployment. It reads a `RunConfig`, a `ModelSettings` and an environment
mapping, and reports what those objects will cause. Anything outside those
three — your network egress rules, your OpenAI account's retention setting,
a proxy, a Zero Data Retention agreement — is invisible here and is listed
in the report as an explicit blind spot rather than silently assumed away.

A tool that reports its own blind spots is usable in a review. A tool that
returns "COMPLIANT" is not.
"""

from __future__ import annotations

import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Any

__all__ = [
    "Severity",
    "Finding",
    "Posture",
    "audit",
    "OPENAI_TRACES_ENDPOINT",
    "BLIND_SPOTS",
]

#: Where the SDK's default span exporter posts, verified from
#: `agents.tracing.processors.BackendSpanExporter`. Named here so the docs,
#: the tests and the report all quote one string.
OPENAI_TRACES_ENDPOINT = "https://api.openai.com/v1/traces/ingest"

#: The default `RunConfig.workflow_name`. A trace named this is a trace you
#: cannot attribute to a service six months later.
DEFAULT_WORKFLOW_NAME = "Agent workflow"


class Severity(str, Enum):
    """Three levels, because five is one more than anyone triages.

    BLOCK is reserved for "data leaves your estate" and "a tenant boundary is
    not enforced". Everything that is merely untidy is WARN. Nothing is
    BLOCK because it is a bad idea; it is BLOCK because it is irreversible or
    invisible.
    """

    BLOCK = "block"
    WARN = "warn"
    INFO = "info"


@dataclass(frozen=True)
class Finding:
    """One thing the configuration will cause.

    `remedy` is mandatory and is a line of code wherever possible. A finding
    without a remedy is a complaint, and reviewers learn to skip tools that
    only complain.
    """

    code: str
    severity: Severity
    subject: str
    detail: str
    remedy: str

    def __str__(self) -> str:  # pragma: no cover - presentation only
        return f"[{self.severity.value}:{self.code}] {self.subject} — {self.detail}"


#: Things this module cannot see. Printed with every report, on purpose.
BLIND_SPOTS: tuple[str, ...] = (
    "Your OpenAI account/org data-retention setting, including any Zero Data "
    "Retention agreement. That is negotiated, not configured, and it is "
    "invisible from inside the process.",
    "Network egress policy. A blocked outbound route makes the tracing "
    "finding moot; an open one makes it real. This module reads objects, not "
    "firewalls.",
    "Whatever your tools do. A tool that writes to a third-party API moves "
    "more data than tracing ever will, and no RunConfig field describes it.",
    "Prompt content. Egress posture is about the pipe, not the payload — see "
    "`redaction.py` and `guardrails.py` for the payload.",
)


@dataclass(frozen=True)
class Posture:
    """The result of an audit."""

    findings: tuple[Finding, ...] = ()
    blind_spots: tuple[str, ...] = BLIND_SPOTS

    @property
    def blocking(self) -> tuple[Finding, ...]:
        return tuple(f for f in self.findings if f.severity is Severity.BLOCK)

    @property
    def warnings(self) -> tuple[Finding, ...]:
        return tuple(f for f in self.findings if f.severity is Severity.WARN)

    @property
    def is_releasable(self) -> bool:
        """No blocking findings.

        Deliberately *not* called `is_compliant`. This function knows about
        three objects. Compliance is a statement about a system.
        """
        return not self.blocking

    def by_code(self, code: str) -> Finding | None:
        for f in self.findings:
            if f.code == code:
                return f
        return None


# ---------------------------------------------------------------------------
# The audit
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Environment parsing
# ---------------------------------------------------------------------------
# The SDK does not have one env parser. It has three, and they disagree:
#
#   OPENAI_AGENTS_DISABLE_TRACING               "true" | "1"
#   OPENAI_AGENTS_TRACE_INCLUDE_SENSITIVE_DATA  "1" | "true" | "yes" | "on"
#   OPENAI_AGENTS_DONT_LOG_*                    "1" | "true"
#
# The first draft of this module used one permissive parser for all three, on
# the reasoning that accepting the union is harmless. It is not. With
# `OPENAI_AGENTS_DISABLE_TRACING=yes`, the runtime leaves tracing ON and the
# permissive audit reported it as off — the audit would have cleared the
# exact configuration it exists to catch.
#
# So each variable gets the parser the runtime actually uses, and each is
# pinned by a test in tests/test_sdk_contract.py. A control that models its
# subject approximately is not a weaker control; it is a wrong one.


def _truthy_strict(value: str | None, default: bool) -> bool:
    """Matches `agents.tracing.provider` and `agents._debug`."""
    if value is None:
        return default
    return value.lower() in ("true", "1")


def _truthy_loose(value: str | None, default: bool) -> bool:
    """Matches `agents.run_config._default_trace_include_sensitive_data`."""
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def audit(
    run_config: Any = None,
    *,
    model_settings: Any = None,
    environ: Mapping[str, str] | None = None,
    trace_processors: Sequence[Any] | None = None,
    tenant_id: str | None = None,
) -> Posture:
    """Report what this configuration will cause.

    Every argument is optional and duck-typed on purpose. This has to run in
    a CI job that has not installed the SDK, in a pre-commit hook, and inside
    a service that already built its RunConfig — so it reads attributes it
    finds and ignores what it does not. `getattr(x, name, sentinel)` rather
    than isinstance checks is a deliberate choice, not laziness: the audit
    should survive an SDK release that renames a field by reporting that it
    could not find it, instead of crashing the service it was meant to guard.

    Args:
        run_config: an `agents.RunConfig`, or anything with its attributes.
        model_settings: an `agents.ModelSettings`. Falls back to
            `run_config.model_settings` when not given.
        environ: environment mapping. Defaults to `os.environ`.
        trace_processors: the processors you have installed. An empty
            sequence means "the SDK default exporter is what will run", which
            is the case that matters.
        tenant_id: if this run serves one tenant, pass it. Enables the
            tenant-attribution checks, which are otherwise skipped rather
            than guessed at.
    """
    env = os.environ if environ is None else environ
    findings: list[Finding] = []
    _missing = object()

    if model_settings is None and run_config is not None:
        candidate = getattr(run_config, "model_settings", None)
        model_settings = candidate

    # -- 1. Does anything leave the process at all? -------------------------
    tracing_disabled = getattr(run_config, "tracing_disabled", _missing)
    env_disabled = _truthy_strict(env.get("OPENAI_AGENTS_DISABLE_TRACING"), False)

    # Worth knowing separately: the SDK reads this variable **once**, on first
    # use, and caches it for the life of the process
    # (`DefaultTraceProvider._refresh_disabled_flag`). Setting it after the
    # first trace has been created does nothing, which is a reasonable design
    # and an unreasonable surprise if you were planning to flip it at runtime
    # during an incident.
    raw_disable = env.get("OPENAI_AGENTS_DISABLE_TRACING")
    if raw_disable is not None and not env_disabled:
        findings.append(
            Finding(
                code="posture:disable-tracing-not-recognised",
                severity=Severity.BLOCK,
                subject=f"OPENAI_AGENTS_DISABLE_TRACING={raw_disable!r} does not disable tracing",
                detail=(
                    "The runtime accepts only 'true' or '1' (case-insensitive) "
                    "for this variable. Any other value — including 'yes', "
                    "'on' and 'TRUE ' with a trailing space — leaves tracing "
                    "enabled, with no warning. Somebody set this intending to "
                    "turn tracing off, and it is on."
                ),
                remedy="OPENAI_AGENTS_DISABLE_TRACING=true",
            )
        )

    if tracing_disabled is _missing:
        findings.append(
            Finding(
                code="posture:unknown-tracing",
                severity=Severity.WARN,
                subject="tracing_disabled could not be read",
                detail=(
                    "No `tracing_disabled` attribute was found on the object "
                    "passed in. Either this is not a RunConfig, or the SDK "
                    "renamed the field. Both are worth knowing; neither is "
                    "safe to treat as 'off'."
                ),
                remedy="Pass the RunConfig you actually run with.",
            )
        )
        tracing_on = True  # assume the dangerous case
    else:
        tracing_on = not bool(tracing_disabled) and not env_disabled

    has_custom_processor = bool(trace_processors)

    if tracing_on and not has_custom_processor:
        findings.append(
            Finding(
                code="egress:default-trace-exporter",
                severity=Severity.BLOCK,
                subject=f"spans are exported to {OPENAI_TRACES_ENDPOINT}",
                detail=(
                    "Tracing is enabled and no trace processor is installed, "
                    "so the SDK's BackendSpanExporter runs and POSTs every "
                    "span to OpenAI, authenticated with OPENAI_API_KEY. This "
                    "is a second data flow, separate from the inference call, "
                    "and it is the one that does not appear on an "
                    "architecture diagram because nobody wrote it."
                ),
                remedy=(
                    "Either `RunConfig(tracing_disabled=True)`, or install a "
                    "processor you own: "
                    "`agents.set_trace_processors([EstateTraceProcessor(sink)])`. "
                    "set_trace_processors REPLACES the defaults; "
                    "add_trace_processor keeps them."
                ),
            )
        )

    # -- 2. If it leaves, what is in it? ------------------------------------
    include_sensitive = getattr(run_config, "trace_include_sensitive_data", _missing)
    if include_sensitive is _missing:
        include_sensitive = _truthy_loose(
            env.get("OPENAI_AGENTS_TRACE_INCLUDE_SENSITIVE_DATA"), True
        )

    if tracing_on and include_sensitive:
        findings.append(
            Finding(
                code="egress:sensitive-span-payloads",
                severity=Severity.BLOCK,
                subject="spans carry model inputs, outputs and tool arguments",
                detail=(
                    "trace_include_sensitive_data is True (its default). "
                    "Spans therefore carry prompt text, completion text and "
                    "tool-call arguments. If the destination is anything you "
                    "do not control, that is the whole conversation, not "
                    "metadata about it."
                ),
                remedy=(
                    "RunConfig(trace_include_sensitive_data=False) keeps the "
                    "spans — shape, timing, token counts, errors — and drops "
                    "the payloads. You lose less debuggability than you "
                    "expect; span structure is most of what you actually read."
                ),
            )
        )

    # The inversion. Worth reporting even when tracing is off, because the
    # engineer's belief about these two flags is the actual finding.
    dont_log_model = _truthy_strict(env.get("OPENAI_AGENTS_DONT_LOG_MODEL_DATA"), True)
    if tracing_on and include_sensitive and dont_log_model:
        findings.append(
            Finding(
                code="posture:log-trace-inversion",
                severity=Severity.WARN,
                subject="local logs are redacted while the remote export is not",
                detail=(
                    "OPENAI_AGENTS_DONT_LOG_MODEL_DATA defaults to True, so "
                    "the SDK's Python logger withholds prompts and "
                    "completions. That flag has no effect on the trace "
                    "exporter. The stricter control is the one on the data "
                    "that never leaves the box."
                ),
                remedy=(
                    "Treat the two as unrelated, because they are. Decide the "
                    "export posture on its own."
                ),
            )
        )

    # -- 3. Server-side retention of the inference call itself --------------
    store = getattr(model_settings, "store", _missing)
    if store is _missing or store is None:
        findings.append(
            Finding(
                code="posture:store-unset",
                severity=Severity.WARN,
                subject="`store` is unset, so the API's own default applies",
                detail=(
                    "The SDK omits `store` from the request when it is None "
                    "(verified in agents/models/openai_responses.py, which "
                    "wraps it in _non_null_or_omit). Whether your request and "
                    "response are retained server-side is then decided by the "
                    "API default and your account settings — neither of which "
                    "is in your repository, and neither of which will send "
                    "you a changelog."
                ),
                remedy=(
                    "Set it explicitly: ModelSettings(store=False) for "
                    "regulated traffic, store=True where you want the "
                    "Responses API to hold state for you. An explicit value "
                    "is a decision a reviewer can read; None is a decision "
                    "somebody else makes for you."
                ),
            )
        )

    retention = getattr(model_settings, "prompt_cache_retention", None)
    if retention == "24h":
        findings.append(
            Finding(
                code="posture:cache-retention-24h",
                severity=Severity.WARN,
                subject="prompt_cache_retention='24h'",
                detail=(
                    "Prompt content is held for 24 hours to serve cache hits. "
                    "That is usually a good trade and occasionally a "
                    "contractual problem. It should be a sentence in your "
                    "data-flow document either way."
                ),
                remedy="ModelSettings(prompt_cache_retention='in_memory') if 24h is not agreed.",
            )
        )

    # -- 4. Can you attribute what you collected? ---------------------------
    workflow_name = getattr(run_config, "workflow_name", _missing)
    if workflow_name == DEFAULT_WORKFLOW_NAME:
        findings.append(
            Finding(
                code="observability:default-workflow-name",
                severity=Severity.WARN,
                subject=f"workflow_name is still {DEFAULT_WORKFLOW_NAME!r}",
                detail=(
                    "Every service in the estate that forgot to set this "
                    "shares one name in the trace UI. The cost lands during "
                    "an incident, which is the worst moment to discover you "
                    "cannot filter."
                ),
                remedy='RunConfig(workflow_name="inbox-triage")',
            )
        )

    if tenant_id is not None:
        group_id = getattr(run_config, "group_id", None)
        if not group_id:
            findings.append(
                Finding(
                    code="tenancy:no-trace-group",
                    severity=Severity.WARN,
                    subject="a tenant was supplied but group_id is unset",
                    detail=(
                        "Traces for every tenant land in one undifferentiated "
                        "stream. Answering 'show me what happened for this "
                        "customer' then becomes a full scan, and answering "
                        "'delete what you hold for this customer' becomes a "
                        "conversation with your legal team."
                    ),
                    remedy="RunConfig(group_id=f'tenant:{tenant_id}')",
                )
            )

        metadata = getattr(run_config, "trace_metadata", None) or {}
        if _looks_like_raw_identifier(metadata):
            findings.append(
                Finding(
                    code="tenancy:pii-in-trace-metadata",
                    severity=Severity.BLOCK,
                    subject="trace_metadata contains something shaped like a person",
                    detail=(
                        "Trace metadata is exported with the span and is not "
                        "covered by trace_include_sensitive_data — that flag "
                        "governs payloads, not the metadata you attached "
                        "yourself. An email address put here for convenience "
                        "is exported unconditionally."
                    ),
                    remedy=(
                        "Attach an opaque tenant key. If you need to resolve "
                        "it to a person, resolve it in your own system, where "
                        "the mapping is subject to your own retention rules."
                    ),
                )
            )

    return Posture(findings=tuple(findings))


_IDENTIFIER_HINTS = ("@", "email", "phone", "ssn", "dob", "address", "name")


def _looks_like_raw_identifier(metadata: Mapping[str, Any]) -> bool:
    """A blunt check, and honest about being one.

    This is a lint, not a DLP scan. It catches the common shape — somebody
    put `{"user": "sam@acme.com"}` in trace metadata because it was handy
    during debugging and it never came out again. It will miss an opaque
    field that happens to hold a national ID.

    `redaction.py` holds the real detectors, and even those are a first pass.
    """
    for key, value in metadata.items():
        blob = f"{key} {value}".lower()
        if any(hint in blob for hint in _IDENTIFIER_HINTS):
            return True
    return False


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def render(posture: Posture) -> str:
    """A report you can paste into a review.

    Kept in this module rather than the example, because the example is not
    the only caller: this is what a CI job prints when the gate fails, and a
    gate whose output nobody can read gets disabled.
    """
    lines: list[str] = []
    order = {Severity.BLOCK: 0, Severity.WARN: 1, Severity.INFO: 2}
    for f in sorted(posture.findings, key=lambda f: (order[f.severity], f.code)):
        lines.append(f"  {f.severity.value.upper():<5}  {f.subject}")
        lines.extend(_wrap(f.detail, indent=9))
        lines.extend(_wrap(f"fix: {f.remedy}", indent=9))
        lines.append("")

    if not posture.findings:
        lines.append("  no findings from the three objects this audit can see.")
        lines.append("")

    lines.append("  This audit cannot see:")
    for spot in posture.blind_spots:
        wrapped = _wrap(spot, indent=6)
        lines.append("    - " + wrapped[0].lstrip())
        lines.extend(wrapped[1:])
    return "\n".join(lines)


def _wrap(text: str, *, indent: int, width: int = 88) -> list[str]:
    """Wrap to a terminal, without a dependency.

    `textwrap` is stdlib, so this is a thin call — but it is worth being
    explicit that the report is meant to be read in a terminal and pasted
    into a review document. An unwrapped 400-character finding is a finding
    people scroll past, and a governance tool that is unpleasant to read
    gets read once.
    """
    import textwrap

    pad = " " * indent
    return textwrap.wrap(
        text,
        width=width - indent,
        initial_indent=pad,
        subsequent_indent=pad,
        # A remedy is a line of code. Splitting `set_trace_processors` across
        # two lines makes it uncopyable, which defeats the point of having a
        # remedy field at all.
        break_long_words=False,
        break_on_hyphens=False,
    )
