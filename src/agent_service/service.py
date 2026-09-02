"""
The whole thing, wired together.

This is the only module in the package that imports the SDK, and the only
one that can call a model. Everything it assembles was built and tested
without one — which is the point being made, not an accident of ordering.

--------------------------------------------------------------------------
What a request actually does
--------------------------------------------------------------------------
    1. Build a SessionKey from (tenant, conversation). The tenant comes from
       your authenticated context. It never comes from the request body.
    2. Audit the RunConfig. In `strict` mode a blocking finding raises
       before any data moves — a governance gate that runs after the call is
       a report, not a gate.
    3. Run the agent with the session, the guardrails and the tool policy.
    4. Whatever comes back, check it on the way out.

--------------------------------------------------------------------------
Why the audit runs per-service rather than per-request
--------------------------------------------------------------------------
Because it would be the same answer every time and it costs microseconds
that belong to a user. `TriageService` audits once at construction and
raises there. The failure then happens at deploy time, in front of whoever
deployed it, instead of at 400 requests per second in front of a customer.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any

from .guardrails import (
    Segment,
    ToolPolicy,
    Trust,
    Verdict,
    check_egress,
    check_injection,
    check_tool_call,
)
from .posture import Posture, audit, render
from .redaction import Redactor
from .session_store import MemoryBackend, RetentionPolicy, ScopedSession, SessionKey
from .tracing import EstateTraceProcessor

logger = logging.getLogger("agent_service")

__all__ = ["TriageRequest", "TriageResult", "TriageService", "PostureError"]


class PostureError(RuntimeError):
    """Raised at construction when the configuration would leak.

    Deliberately a construction-time error rather than a request-time one.
    A service that starts and then refuses every request is an outage with
    extra steps; a service that refuses to start is a deploy that failed,
    which is a thing organisations already know how to handle.
    """


@dataclass(frozen=True)
class TriageRequest:
    tenant_id: str
    conversation_id: str
    #: What the human typed.
    user_message: str
    #: What the system fetched — the email body, the ticket, the document.
    #: Kept separate from `user_message` all the way down, because the
    #: guardrail layer's one real idea is that these are different things.
    fetched_content: Sequence[tuple[str, str]] = ()

    def segments(self) -> list[Segment]:
        return [
            Segment(self.user_message, Trust.USER, "user turn"),
            *(
                Segment(text, Trust.UNTRUSTED, label)
                for label, text in self.fetched_content
            ),
        ]


@dataclass(frozen=True)
class TriageResult:
    output: str | None
    refused: bool = False
    reason: str = ""
    suspicious: bool = False
    #: The guardrail verdicts, so a caller can log or alert on them without
    #: re-deriving anything. Returning these rather than logging internally
    #: keeps the library out of your observability decisions.
    verdicts: tuple[Verdict, ...] = ()


class TriageService:
    """A configured agent, its session store, and its guardrails.

    Construct once per process. The audit, the redactor and the trace
    processor are all process-level concerns, and rebuilding them per
    request would be both slow and — for the redactor's key — wrong.
    """

    def __init__(
        self,
        *,
        instructions: str,
        tools: Sequence[Any] = (),
        policy: ToolPolicy,
        model: str = "gpt-5-nano",
        backend: Any = None,
        retention: RetentionPolicy | None = None,
        redactor: Redactor | None = None,
        trace_sink: Callable[[Any], None] | None = None,
        strict: bool = True,
    ) -> None:
        from agents import Agent, ModelSettings, RunConfig, set_trace_processors

        self._redactor = redactor or Redactor()
        if self._redactor.key_is_ephemeral:
            # Not fatal — a per-process key is the safe degraded mode — but
            # it must be said out loud, because the symptom (placeholders
            # that stop correlating across replicas) is invisible until
            # somebody is trying to trace an incident.
            logger.warning(
                "REDACTION_KEY is unset: redaction placeholders will not "
                "correlate across processes"
            )

        self._backend = backend or MemoryBackend()
        self._retention = retention
        self._policy = policy

        # Install the estate processor BEFORE building the RunConfig, and use
        # set_ rather than add_: set_ replaces the SDK's default exporter,
        # add_ would leave it running alongside. Getting this backwards
        # produces a system that looks correct from your sink.
        processors: list[Any] = []
        if trace_sink is not None:
            processor = EstateTraceProcessor(trace_sink, redactor=self._redactor)
            set_trace_processors([processor])
            processors.append(processor)

        self._run_config = RunConfig(
            workflow_name="inbox-triage",
            trace_include_sensitive_data=False,
            tracing_disabled=trace_sink is None,
            model_settings=ModelSettings(store=False),
        )

        self.posture: Posture = audit(
            self._run_config,
            model_settings=self._run_config.model_settings,
            trace_processors=processors,
        )
        if strict and not self.posture.is_releasable:
            raise PostureError(
                "refusing to start with a leaking configuration:\n"
                + render(self.posture)
            )

        self._agent = Agent(
            name="inbox-triage",
            instructions=instructions,
            model=model,
            tools=list(tools),
        )

    # -- the request path --------------------------------------------------

    def session_for(self, request: TriageRequest) -> ScopedSession:
        return ScopedSession(
            SessionKey(request.tenant_id, request.conversation_id),
            self._backend,
            retention=self._retention or RetentionPolicy(),
        )

    def screen(self, request: TriageRequest) -> Verdict:
        """The pre-flight check. Cheap, deterministic, no model involved."""
        return check_injection(request.segments())

    def may_call(self, tool_name: str, arguments: Any, *, suspicious: bool) -> Verdict:
        return check_tool_call(tool_name, arguments, self._policy, suspicious=suspicious)

    async def run(self, request: TriageRequest) -> TriageResult:
        """One turn.

        Note what is NOT here: a try/except around the model call that
        returns a friendly string. Swallowing an inference failure into a
        200 response is how a broken agent runs for a week — the caller
        should see the exception and decide.
        """
        from agents import Runner

        screening = self.screen(request)
        session = self.session_for(request)

        # Per-turn group_id, so a trace is filterable to a tenant without a
        # join and deletable per tenant without a conversation with legal.
        run_config = _with_group(self._run_config, f"tenant:{request.tenant_id}")

        result = await Runner.run(
            self._agent,
            request.user_message,
            session=session,
            run_config=run_config,
            context={"suspicious": screening.tripped},
        )

        output = result.final_output if isinstance(result.final_output, str) else str(
            result.final_output
        )
        egress = check_egress(output, redactor=self._redactor)
        if egress.tripped:
            # Withhold rather than redact-and-send. A model that emitted a
            # secret once will do it again, and you want that loud.
            return TriageResult(
                output=None,
                refused=True,
                reason=egress.code,
                suspicious=screening.tripped,
                verdicts=(screening, egress),
            )

        return TriageResult(
            output=output,
            suspicious=screening.tripped,
            verdicts=(screening, egress),
        )


def _with_group(run_config: Any, group_id: str) -> Any:
    """A copy of the RunConfig with a tenant group set.

    `dataclasses.replace` rather than mutation: the service's RunConfig is
    shared across concurrent requests, and mutating it per turn is a race
    that shows up as traces attributed to the wrong customer — which is
    both a bug and a disclosure.
    """
    import dataclasses

    return dataclasses.replace(run_config, group_id=group_id)
