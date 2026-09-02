# 04 · Observability

The SDK's tracing is good, and the argument here is not against it. It is
about *where the spans land* and *what is in them* — two questions that
have one answer by default and should have two decisions.

---

## The one rule

**A trace processor must never raise.**

It runs inside the request path. An exception there turns an observability
problem into an availability problem, and it does so on your busiest day,
because that is when the unusual span shows up.

```python
def _emit(self, kind, obj, *, ending):
    try:
        ...
    except Exception:
        self._failures += 1
        logger.warning("trace processor swallowed an exception", exc_info=True)
```

With the counter exposed:

```python
processor.failures   # a health check can report "telemetry degraded"
```

Silence is not the same as success. Without a counter, a processor
swallowing every span looks exactly like a quiet system, and nobody
investigates a quiet system.

---

## `set_` replaces, `add_` appends

```python
agents.set_trace_processors([EstateTraceProcessor(sink)])   # REPLACES
agents.add_trace_processor(EstateTraceProcessor(sink))      # ADDS
```

Reach for `add_` and the default OpenAI exporter keeps running alongside
yours. Your spans arrive in your sink, everything looks correct from where
you are standing, and the copy to `api.openai.com` continues.

If you want both, say so on purpose. There is a test pinning this
distinction against the real SDK, because it is exactly the kind of detail a
refactor tidies away.

---

## What to keep, and what to drop

By default `EstateTraceProcessor` drops payloads and keeps shape:

```
span   generation   {'model': 'gpt-5-nano',
                     'input': '<list:3items>',
                     'output': '<text:412chars>',
                     'usage': {'input_tokens': 812, 'output_tokens': 96}}
```

**Replaced, not deleted.** A missing key and an empty input look identical
after deletion, and telling those apart is most of what span-reading is for.
`<absent>` and `<text:0chars>` are different facts.

You keep: which agent ran, which tools were called, how long each took,
token counts, error shapes, the handoff graph. That is most of what anyone
actually reads. Payloads are what you reach for on the tenth investigation —
and by then you want them in your own store under your own retention rules
anyway, not in a vendor's trace UI.

`include_payloads=True` is a legitimate choice for a sink inside your own
boundary. It is not a choice to ship raw secrets: payloads are still
redacted on the way out.

---

## Errors get redacted too

An exception message quoting the request body is a leak with a stack trace
attached, and it bypasses every payload control because it is not a payload.

```python
error = self._redactor.redact(error)
```

This is the single most common way a secret reaches a log.

---

## The sink is yours, and it should be cheap

```python
class Sink(Protocol):
    def __call__(self, record: SpanRecord) -> None: ...
```

`EstateTraceProcessor` is called **synchronously from the run**. A sink that
does a blocking HTTP POST per span adds its latency to every turn.

Write to a bounded queue and drain it elsewhere. When the queue is full,
drop and count. Dropping telemetry under load is correct; adding
backpressure to a user request in order to record that the user request
happened is not.

`CollectingSink` (used by the tests and examples) does the bounded part and
drops the **oldest** when full — the newest spans describe whatever is
currently going wrong.

---

## `SpanRecord` does not import the SDK

```python
@dataclass(frozen=True)
class SpanRecord:
    kind: str          # "trace" | "span"
    trace_id: str
    span_id: str | None
    parent_id: str | None
    span_type: str | None
    name: str | None
    started_at: str | None
    ended_at: str | None
    error: dict | None
    data: dict
```

Deliberately flat, and `EstateTraceProcessor` deliberately does not subclass
`agents.TracingProcessor` — the SDK checks structurally, so inheritance buys
nothing and costs the dependency.

Log-shipping code tends to live in a different repository owned by a
different team. Keeping it free of an agent framework is the difference
between that code having tests and not. There is a test asserting the module
imports nothing from `agents`.

---

## Attribution: two fields, both cheap

```python
RunConfig(
    workflow_name="inbox-triage",       # not "Agent workflow"
    group_id=f"tenant:{tenant_id}",
)
```

`workflow_name` defaults to `"Agent workflow"`. Every service in the estate
that forgot to set it shares one name, and the cost lands during an
incident — the worst possible moment to discover you cannot filter.

`group_id` is the one that matters later. Without it, "show me what happened
for this customer" is a full scan, and "delete what you hold for this
customer" is a conversation with your legal team.

> **`trace_metadata` is exported regardless of
> `trace_include_sensitive_data`.** That flag governs payloads, not the
> metadata you attached yourself. An email address put there for
> convenience during debugging ships with every span, unconditionally. The
> audit raises this as **BLOCK**, and it is the finding people are most
> surprised by, because they set the flag and reasonably assumed it covered
> everything.

Attach an opaque tenant key. If you need to resolve it to a person, resolve
it in your own system, where the mapping is subject to your own rules.

---

**Next:** [05 · Deployment](05-deployment.md)
