"""
Guardrails: the deterministic half.

--------------------------------------------------------------------------
The claim this module refuses to make
--------------------------------------------------------------------------
It does not detect prompt injection. Nothing does, reliably. Injection is a
natural-language problem with an adversary on the other end, and a pattern
list is a speed bump that the adversary reads before they write.

What this module does is narrower and actually holds:

  1. **Provenance.** Content is tagged by where it came from. Instructions
     addressed to the agent are only suspicious when they arrive in content
     the *agent fetched*, never in what the user typed. That distinction
     removes most of the false positives that make teams switch these checks
     off, and it is the only part of injection defence that is decidable.

  2. **Least privilege on tools.** The tool-argument guardrail is the control
     that survives contact with a real attacker, because it does not care
     whether the model was persuaded. A persuaded model calling
     `refund(amount=900000)` is stopped by a bound on `amount`, and would not
     have been stopped by any amount of reading the prompt.

  3. **Egress checking on the way out.** Whatever happened in the middle, a
     secret in the final output is a finding. This is the last cheap moment.

Of the three, only the second is a control. The first is triage and the
third is a net. The repository says this in the README as well, because a
guardrail module that lets a reader believe it stops injection has done more
harm than the injection would have.

--------------------------------------------------------------------------
Shape
--------------------------------------------------------------------------
Every check is a pure function returning a `Verdict`. The SDK adapters at the
bottom are three-line wrappers. That split is deliberate: the decision logic
is then testable without an API key, a network, or a model — which is what
makes it possible to have a test per rule instead of a smoke test per module.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .redaction import Redactor

__all__ = [
    "Trust",
    "Segment",
    "Verdict",
    "check_injection",
    "check_egress",
    "ToolPolicy",
    "check_tool_call",
    "INJECTION_PATTERNS",
]


class Trust(str, Enum):
    """Where a piece of content came from.

    The three-way split matters more than it looks. Most systems collapse
    USER and UNTRUSTED into "input", and then cannot tell the difference
    between a person asking for something unusual and a fetched document
    asking on their behalf. That collapse is the reason injection filters are
    simultaneously too noisy to keep on and too weak to rely on.
    """

    #: Your own system prompt and templates. Trusted absolutely — if this is
    #: compromised you have a different problem.
    OPERATOR = "operator"

    #: What the human typed. Trusted to *ask*, not to authorise. A user may
    #: legitimately say "ignore the previous draft"; that is not an attack,
    #: and a filter that trips on it will be removed within the week.
    USER = "user"

    #: Anything the system pulled in: email bodies, web pages, file contents,
    #: tool results, records written by another tenant. This is the only
    #: place injection can arrive from, by definition — everything else the
    #: user or the operator said on purpose.
    UNTRUSTED = "untrusted"


@dataclass(frozen=True)
class Segment:
    """A span of content with a known origin.

    `label` is for the finding message ("the email body", "search result 3").
    An operator reading an alert needs to know *which* untrusted thing, and
    reconstructing that from offsets at 3am is not a good use of anyone.
    """

    text: str
    trust: Trust
    label: str = "content"


@dataclass(frozen=True)
class Verdict:
    """The result of one check.

    `tripped` is the decision. `code` and `detail` are for the operator.
    `evidence` is the matched text, already redacted where the check runs on
    content that might carry secrets — an alert that quotes the API key it
    found has moved the key into your alerting system.
    """

    tripped: bool
    code: str = ""
    detail: str = ""
    evidence: tuple[str, ...] = ()

    @property
    def allowed(self) -> bool:
        return not self.tripped


_OK = Verdict(tripped=False)


# ---------------------------------------------------------------------------
# 1 · Injection tripwire — provenance-scoped
# ---------------------------------------------------------------------------

#: Shapes that mean "stop doing your job and do mine instead". These catch
#: the unsophisticated majority and nothing else, which is exactly the claim
#: made for them.
#:
#: Note what is NOT here: anything about the *content* of a request. "Send
#: money to X" is not on this list, because deciding whether that is
#: legitimate is the tool policy's job and it can actually decide it.
INJECTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "override",
        re.compile(
            r"\b(?:ignore|disregard|forget|override)\b[^.\n]{0,40}?"
            r"\b(?:previous|prior|earlier|above|system|all)\b"
            r"[^.\n]{0,30}?\b(?:instruction|prompt|rule|direction|message)s?\b",
            re.IGNORECASE,
        ),
    ),
    (
        "role-reassign",
        re.compile(
            r"\byou\s+are\s+(?:now|actually)\b|"
            r"\bfrom\s+now\s+on\s+you\b|"
            r"\bnew\s+(?:system\s+)?(?:instruction|prompt|role)s?\s*:",
            re.IGNORECASE,
        ),
    ),
    (
        "exfiltrate-prompt",
        re.compile(
            r"\b(?:reveal|repeat|print|show|output|dump)\b[^.\n]{0,30}?"
            r"\b(?:system\s+prompt|your\s+instructions|initial\s+prompt)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "impersonate-frame",
        # A fetched document that opens a fake turn boundary is trying to end
        # the operator's context. There is no innocent reason for an email
        # body to contain this.
        re.compile(
            r"(?:^|\n)\s*(?:<\|?(?:im_start|system|assistant)\|?>|"
            r"###\s*(?:system|instruction)|\[\s*system\s*\])",
            re.IGNORECASE,
        ),
    ),
    (
        "tool-coercion",
        re.compile(
            r"\b(?:call|invoke|use|execute)\s+the\s+\w+\s+tool\b|"
            r"\bwithout\s+(?:asking|confirming|telling)\s+the\s+user\b",
            re.IGNORECASE,
        ),
    ),
)


def check_injection(
    segments: Sequence[Segment],
    *,
    patterns: Iterable[tuple[str, re.Pattern[str]]] = INJECTION_PATTERNS,
) -> Verdict:
    """Trip only on instruction-shaped text inside UNTRUSTED segments.

    The scoping is the whole design. Run these same patterns across the user
    turn and you will block "ignore the previous instructions I gave you, I
    meant something else" — a sentence people say constantly — and your team
    will correctly conclude the check is noise.

    Returns a verdict, not an exception. Some deployments want to strip the
    offending segment and continue rather than fail the request, and that is
    a policy decision this function does not get to make.
    """
    hits: list[str] = []
    codes: list[str] = []
    for seg in segments:
        if seg.trust is not Trust.UNTRUSTED:
            continue
        for name, pattern in patterns:
            m = pattern.search(seg.text)
            if m:
                codes.append(name)
                hits.append(f"{seg.label}: {_clip(m.group(0))}")

    if not hits:
        return _OK
    return Verdict(
        tripped=True,
        code="injection:" + ",".join(sorted(set(codes))),
        detail=(
            "Instruction-shaped text appeared in content the system fetched "
            "rather than content the user wrote. This is a signal to "
            "investigate and a reason to withhold tool access for this turn. "
            "It is not proof of an attack, and its absence is not proof of "
            "safety."
        ),
        evidence=tuple(hits),
    )


def _clip(text: str, limit: int = 120) -> str:
    flat = " ".join(text.split())
    return flat if len(flat) <= limit else flat[: limit - 1] + "…"


# ---------------------------------------------------------------------------
# 2 · Tool policy — the control that actually holds
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ToolPolicy:
    """What a tool is allowed to be called with.

    This is the part of the module that stops a real attack, and it is the
    least interesting to read, which is roughly the ratio you should expect
    from security code.

    `allowed_tools` is an allowlist and not a denylist. A denylist protects
    you from the tools you thought of. When somebody adds `send_email` next
    quarter, an allowlist fails closed and a denylist fails open, and nobody
    is watching either way.
    """

    allowed_tools: frozenset[str]
    #: tool name -> argument name -> predicate. A predicate returning False
    #: rejects the call. Kept as plain callables so a policy can express
    #: "amount under 10_000" or "path inside /srv/data" without this module
    #: inventing a rule language.
    argument_checks: Mapping[str, Mapping[str, Callable[[Any], bool]]] = field(
        default_factory=dict
    )
    #: Tools that must never run when the turn saw untrusted instruction-shaped
    #: content. This is how the tripwire above becomes an actual control: it
    #: does not decide whether an attack happened, it downgrades privilege
    #: while the answer is unclear.
    revoke_when_suspicious: frozenset[str] = frozenset()


def check_tool_call(
    tool_name: str,
    arguments: Any,
    policy: ToolPolicy,
    *,
    suspicious: bool = False,
) -> Verdict:
    """Decide whether one tool call may proceed.

    `arguments` accepts a mapping or a JSON string, because the SDK hands you
    `tool_arguments` as a JSON string and every test in the world wants to
    pass a dict.

    Unparseable arguments are **rejected**, not passed through. That is worth
    stating because the tempting alternative — "if I cannot parse it I cannot
    judge it, so allow it" — inverts the failure direction of the one control
    in this file that has to fail closed.
    """
    if tool_name not in policy.allowed_tools:
        return Verdict(
            tripped=True,
            code="tool:not-allowlisted",
            detail=(
                f"{tool_name!r} is not in this agent's allowlist. Either it was "
                "added to the agent without being added to the policy, or the "
                "model invented it."
            ),
        )

    if suspicious and tool_name in policy.revoke_when_suspicious:
        return Verdict(
            tripped=True,
            code="tool:revoked-while-suspicious",
            detail=(
                f"{tool_name!r} is withheld for this turn because untrusted "
                "content in the input carried instructions. The turn can still "
                "complete with read-only tools; it cannot take an action."
            ),
        )

    if isinstance(arguments, str):
        try:
            arguments = json.loads(arguments) if arguments.strip() else {}
        except json.JSONDecodeError:
            return Verdict(
                tripped=True,
                code="tool:unparseable-arguments",
                detail=(
                    "Tool arguments were not valid JSON. Rejecting: a control "
                    "that cannot read its input must not approve it."
                ),
            )

    if not isinstance(arguments, Mapping):
        return Verdict(
            tripped=True,
            code="tool:unparseable-arguments",
            detail=f"Tool arguments were {type(arguments).__name__}, expected an object.",
        )

    checks = policy.argument_checks.get(tool_name, {})
    for arg_name, predicate in checks.items():
        if arg_name not in arguments:
            return Verdict(
                tripped=True,
                code="tool:missing-checked-argument",
                detail=(
                    f"{tool_name!r} requires {arg_name!r} and it was absent. A "
                    "constrained argument that can be omitted is not a "
                    "constraint."
                ),
            )
        try:
            ok = predicate(arguments[arg_name])
        except Exception:
            # A predicate that raises on hostile input is itself the finding.
            # Treating the exception as a rejection keeps the failure closed.
            ok = False
        if not ok:
            return Verdict(
                tripped=True,
                code="tool:argument-rejected",
                detail=f"{tool_name}.{arg_name} failed its policy check.",
            )

    return _OK


# ---------------------------------------------------------------------------
# 3 · Egress check — the net
# ---------------------------------------------------------------------------


def check_egress(
    text: str,
    *,
    redactor: Redactor | None = None,
    block_labels: frozenset[str] = frozenset(
        {"openai_key", "aws_key", "github_token", "private_key", "bearer", "ssn", "card"}
    ),
) -> Verdict:
    """Look for things that must not appear in a final answer.

    The default block list is secrets and financial identifiers, not all PII.
    A support agent answering "what address do you have for me?" is *supposed*
    to say an address, and a guardrail that blocks it is a guardrail that
    gets an exception carved into it until it means nothing.

    Blocking the categories that have no legitimate reason to be in a
    generated answer is a check that stays on. That is the whole selection
    criterion.

    Evidence is redacted before it is returned, so the alert about the leaked
    key does not itself contain the key.
    """
    red = redactor or Redactor()
    found = red.findings(text)
    bad = [(label, value) for label, value in found if label in block_labels]
    if not bad:
        return _OK
    return Verdict(
        tripped=True,
        code="egress:" + ",".join(sorted({label for label, _ in bad})),
        detail=(
            "The final output contains a value that has no legitimate reason "
            "to be generated. Withhold the message; do not redact and send, "
            "because a model that produced a secret once will produce it "
            "again and you want that to be loud."
        ),
        evidence=tuple(red.token(label, value) for label, value in bad),
    )


# ---------------------------------------------------------------------------
# SDK adapters
# ---------------------------------------------------------------------------
# Thin on purpose. Everything above is importable and testable with no SDK
# installed; these three functions are the only place that changes if the
# SDK's guardrail signatures move.


def build_input_guardrail(segmenter: Callable[[Any], Sequence[Segment]]):
    """Wrap `check_injection` as an SDK input guardrail.

    `segmenter` is yours to write, and it is the interesting part: it is the
    function that knows which parts of your input came from an email body and
    which the user typed. This package cannot know that, and a default that
    guessed would be a default that marked everything USER and quietly
    disabled the check.
    """
    from agents import GuardrailFunctionOutput, input_guardrail  # local: optional dep

    @input_guardrail
    async def injection_tripwire(ctx, agent, input) -> GuardrailFunctionOutput:
        verdict = check_injection(segmenter(input))
        return GuardrailFunctionOutput(
            output_info={
                "code": verdict.code,
                "detail": verdict.detail,
                "evidence": list(verdict.evidence),
            },
            tripwire_triggered=verdict.tripped,
        )

    return injection_tripwire


def build_output_guardrail(redactor: Redactor | None = None):
    """Wrap `check_egress` as an SDK output guardrail."""
    from agents import GuardrailFunctionOutput, output_guardrail

    @output_guardrail
    async def egress_check(ctx, agent, output) -> GuardrailFunctionOutput:
        text = output if isinstance(output, str) else str(output)
        verdict = check_egress(text, redactor=redactor)
        return GuardrailFunctionOutput(
            output_info={"code": verdict.code, "evidence": list(verdict.evidence)},
            tripwire_triggered=verdict.tripped,
        )

    return egress_check


def build_tool_input_guardrail(
    policy: ToolPolicy, *, is_suspicious: Callable[[Any], bool] = lambda ctx: False
):
    """Wrap `check_tool_call` as an SDK tool-input guardrail.

    Uses `reject_content` rather than `raise_exception`. The difference is
    the difference between a service that degrades and one that 500s: a
    rejection hands the model a message it can reason about ("that call was
    refused, tell the user why"), whereas an exception ends the run and the
    user sees nothing useful.

    Raise instead when the rejection itself is the incident and you want a
    page rather than a graceful answer.
    """
    from agents import ToolGuardrailFunctionOutput, tool_input_guardrail

    @tool_input_guardrail
    def tool_policy_check(data) -> ToolGuardrailFunctionOutput:
        verdict = check_tool_call(
            data.context.tool_name,
            data.context.tool_arguments,
            policy,
            suspicious=is_suspicious(data.context),
        )
        if verdict.allowed:
            return ToolGuardrailFunctionOutput.allow()
        return ToolGuardrailFunctionOutput.reject_content(
            message=f"Refused by tool policy ({verdict.code}). {verdict.detail}",
            output_info={"code": verdict.code},
        )

    return tool_policy_check
