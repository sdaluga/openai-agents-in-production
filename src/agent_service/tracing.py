"""
Keep your traces in your own estate.

--------------------------------------------------------------------------
What this replaces
--------------------------------------------------------------------------
With no processor installed, the SDK exports every span to
`https://api.openai.com/v1/traces/ingest`, authenticated with your
`OPENAI_API_KEY`, carrying prompts, completions and tool arguments (see
`posture.py`, which reports exactly that, and the tests that verify it).

For a lot of teams that is fine and the trace UI is genuinely good. For a
regulated workload it is a second data flow to a third party, and the fact
that it was never a decision is what makes it a finding.

`EstateTraceProcessor` sends spans to a sink you own, redacted on the way
out. It is roughly a hundred lines because it should be — the interesting
part of observability is what you do with the spans, not how you catch them.

--------------------------------------------------------------------------
Installing it: the one-word difference that matters
--------------------------------------------------------------------------
    agents.set_trace_processors([EstateTraceProcessor(sink)])   # REPLACES
    agents.add_trace_processor(EstateTraceProcessor(sink))      # ADDS

`add_` keeps the default OpenAI exporter running alongside yours, which is
almost never what somebody reaching for this class wants and is impossible to
notice from the outside — your spans arrive in your sink, everything looks
correct, and the copy to OpenAI continues. If you want both, say so on
purpose. There is a test that pins this distinction against the real SDK,
because it is the kind of thing that gets "simplified" during a refactor.

--------------------------------------------------------------------------
The one rule
--------------------------------------------------------------------------
**A trace processor must never raise.** It runs inside the request path. An
exception here turns an observability problem into an availability problem,
and it does so on your busiest day, because that is when the unusual span
shows up. Every callback below is wrapped, failures are counted rather than
propagated, and the counter is exposed so a health check can see that
telemetry is degraded — silence is not the same as success, and the
difference must be visible somewhere.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from typing import Any, Protocol

from .redaction import Redactor

__all__ = ["SpanRecord", "EstateTraceProcessor", "CollectingSink"]

logger = logging.getLogger("agent_service.tracing")


@dataclass(frozen=True)
class SpanRecord:
    """One exportable span, already redacted.

    A flat dict-ish record rather than the SDK's span object, for one reason:
    a sink should be writable against this module without importing the SDK.
    That keeps the log-shipping code, which tends to live in a different
    repository owned by a different team, free of a dependency on an agent
    framework.
    """

    kind: str  # "trace" | "span"
    trace_id: str
    span_id: str | None
    parent_id: str | None
    span_type: str | None
    name: str | None
    started_at: str | None
    ended_at: str | None
    error: dict[str, Any] | None
    data: dict[str, Any]


class Sink(Protocol):
    """Where records go. Must not raise; must not block for long.

    "Must not block for long" is the constraint people discover late. This
    processor is called synchronously from the run, so a sink that does a
    blocking HTTP POST per span adds its latency to every turn. Write to a
    bounded queue and drain it elsewhere — and when the queue is full, drop
    and count. Dropping telemetry under load is correct; adding backpressure
    to a user request in order to record that the user request happened is
    not.
    """

    def __call__(self, record: SpanRecord) -> None: ...


class CollectingSink:
    """An in-memory sink, for tests and for the examples.

    Bounded, because an unbounded collector in a test suite is a slow test
    and an unbounded collector anywhere else is an outage. When full it drops
    the *oldest* and increments `dropped` — the newest spans are the ones
    that describe whatever is currently going wrong.
    """

    def __init__(self, max_records: int = 10_000) -> None:
        self.records: list[SpanRecord] = []
        self.dropped = 0
        self._max = max_records

    def __call__(self, record: SpanRecord) -> None:
        self.records.append(record)
        if len(self.records) > self._max:
            overflow = len(self.records) - self._max
            del self.records[:overflow]
            self.dropped += overflow


class EstateTraceProcessor:
    """A `TracingProcessor` that redacts and forwards to a sink you own.

    Deliberately does not subclass `agents.TracingProcessor`. The SDK checks
    structurally, and not inheriting means this class — and the sink code
    written against it — imports nothing from the SDK. A team can unit-test
    their shipping path without installing an agent framework, which is the
    difference between that test existing and not.
    """

    def __init__(
        self,
        sink: Sink,
        *,
        redactor: Redactor | None = None,
        include_payloads: bool = False,
    ) -> None:
        self._sink = sink
        self._redactor = redactor or Redactor()
        self._include_payloads = include_payloads
        self._failures = 0
        self._lock = threading.Lock()

    @property
    def failures(self) -> int:
        """How many callbacks have swallowed an exception.

        Exposed so a health check can report "telemetry degraded" instead of
        the pipeline going quiet and everyone assuming things are calm.
        """
        return self._failures

    # -- TracingProcessor surface -----------------------------------------

    def on_trace_start(self, trace: Any) -> None:
        self._emit("trace", trace, ending=False)

    def on_trace_end(self, trace: Any) -> None:
        self._emit("trace", trace, ending=True)

    def on_span_start(self, span: Any) -> None:
        # Start events carry no outcome and roughly double the volume. Kept
        # anyway, without payloads, because a span that never ends is the
        # signal you want when something hangs — and that signal exists only
        # in the start event.
        self._emit("span", span, ending=False)

    def on_span_end(self, span: Any) -> None:
        self._emit("span", span, ending=True)

    def force_flush(self) -> None:
        """No-op: this processor holds nothing.

        Buffering belongs in the sink, which is the component that knows
        whether it is writing to a file, a queue or a socket. A flush that
        does nothing is better than a buffer nobody knew was there.
        """

    def shutdown(self) -> None:
        """Also a no-op, for the same reason."""

    # -- internals ---------------------------------------------------------

    def _emit(self, kind: str, obj: Any, *, ending: bool) -> None:
        try:
            record = self._to_record(kind, obj, ending=ending)
            if record is not None:
                self._sink(record)
        except Exception:  # noqa: BLE001 - see the module docstring
            with self._lock:
                self._failures += 1
            # exc_info stays on: the traceback is local, and this is the one
            # place where losing the detail costs you the whole investigation.
            logger.warning("trace processor swallowed an exception", exc_info=True)

    def _to_record(self, kind: str, obj: Any, *, ending: bool) -> SpanRecord | None:
        span_data = getattr(obj, "span_data", None)

        data: dict[str, Any] = {}
        if ending and span_data is not None:
            exported = span_data.export()
            data = exported if isinstance(exported, dict) else {"export": exported}
            if not self._include_payloads:
                data = _drop_payloads(data)
            data = self._redactor.redact(data)

        error = getattr(obj, "error", None)
        if error is not None:
            # Errors carry model text often enough that redacting them is not
            # optional. An unredacted exception message is the most common
            # way a secret reaches a log.
            error = self._redactor.redact(
                error if isinstance(error, dict) else {"message": str(error)}
            )

        return SpanRecord(
            kind=kind,
            trace_id=str(getattr(obj, "trace_id", "") or ""),
            span_id=getattr(obj, "span_id", None),
            parent_id=getattr(obj, "parent_id", None),
            span_type=getattr(span_data, "type", None),
            name=getattr(obj, "name", None) or getattr(span_data, "name", None),
            started_at=getattr(obj, "started_at", None),
            ended_at=getattr(obj, "ended_at", None),
            error=error,
            data=data,
        )


#: Fields on the SDK's span-data types that hold model or tool payloads.
#: Dropped unless `include_payloads=True`, so the default posture of this
#: processor matches the recommendation in `posture.py` rather than
#: contradicting it — a library that ships the opposite of its own advice is
#: how advice stops being followed.
_PAYLOAD_FIELDS = frozenset({"input", "output", "result", "arguments", "instructions"})


def _drop_payloads(data: dict[str, Any]) -> dict[str, Any]:
    """Remove payload fields, keep shape.

    Replaces rather than deletes, so the *presence* of an input is still
    visible in the trace even when its content is not. A missing key and an
    empty input look identical after deletion, and telling those apart is
    most of what span reading is for.
    """
    out: dict[str, Any] = {}
    for key, value in data.items():
        if key in _PAYLOAD_FIELDS:
            out[key] = _shape_of(value)
        else:
            out[key] = value
    return out


def _shape_of(value: Any) -> str:
    if value is None:
        return "<absent>"
    if isinstance(value, str):
        return f"<text:{len(value)}chars>"
    if isinstance(value, (list, tuple)):
        return f"<list:{len(value)}items>"
    if isinstance(value, dict):
        return f"<object:{len(value)}keys>"
    return f"<{type(value).__name__}>"
