# 01 · What the defaults do

Every fact on this page is pinned by a test in
[`tests/test_sdk_contract.py`](../tests/test_sdk_contract.py) against the
installed SDK. Documentation that asserts something about a dependency is
true on the day it was written; a test is true on the day it is run.

Verified against `openai-agents` **0.22.0**.

---

## The three defaults

```python
from agents import Agent, Runner

agent = Agent(name="Assistant", instructions="You are a helpful assistant")
result = Runner.run_sync(agent, "Summarise this customer email: ...")
```

Six lines from the quickstart, and three things are now true that nobody
chose:

| | Default | Consequence |
|---|---|---|
| `RunConfig.tracing_disabled` | `False` | tracing is **on** |
| default span exporter | installed | spans POST to `https://api.openai.com/v1/traces/ingest`, authenticated with `OPENAI_API_KEY` |
| `RunConfig.trace_include_sensitive_data` | `True` | those spans carry prompts, completions and tool-call arguments |

Together: **a second data flow, carrying the conversation, to a third
party, that does not appear on your architecture diagram** — because nobody
drew it.

None of this is hidden. It is all documented, and for a prototype it is a
good trade: the trace UI is genuinely useful and the friction of setting it
up is zero. The failure is that a default reads as a decision somebody
already made on your behalf, so nobody re-opens it. Then a data-residency
question arrives eleven months later and the answer takes three days to
establish.

```bash
python examples/01-audit-your-defaults/audit_defaults.py
```

---

## The inversion

This is the part that catches careful people.

```
OPENAI_AGENTS_DONT_LOG_MODEL_DATA   default True    ← local logs redacted
OPENAI_AGENTS_DONT_LOG_TOOL_DATA    default True    ← local logs redacted
trace_include_sensitive_data        default True    ← remote export verbose
```

The `DONT_LOG_*` flags govern the SDK's **Python logger**. They have no
effect on the trace exporter. So the shipped posture is: strict on the data
that never leaves the process, permissive on the data that leaves it.

An engineer reads "don't log model data: true", concludes the SDK is
careful about this, and never opens the exporter. That is not carelessness;
it is a correct inference from a misleading pair of names.

`posture.py` raises `posture:log-trace-inversion` specifically for the
configuration where both are true at once — the profile of somebody who
thought about this and stopped one layer short. It is the middle column in
example 01.

---

## Two environment variables, three parsers

```
OPENAI_AGENTS_DISABLE_TRACING                "true" | "1"
OPENAI_AGENTS_TRACE_INCLUDE_SENSITIVE_DATA   "1" | "true" | "yes" | "on"
OPENAI_AGENTS_DONT_LOG_*                     "1" | "true"
```

`OPENAI_AGENTS_DISABLE_TRACING=yes` **does not disable tracing.** It is not
an error, there is no warning, and the deployment that set it believes the
matter is closed.

This module's first draft used one permissive parser for all three, on the
reasoning that accepting the union was harmless. It would have reported a
clean posture for exactly the configuration it exists to catch. That bug is
now `posture:disable-tracing-not-recognised`, which is a **blocking**
finding: somebody tried to turn tracing off and it is still on, and that is
a different — worse — situation than never having tried.

**And it is read once.** `DefaultTraceProvider` caches the value on first
use for the life of the process. Exporting it into a running container does
nothing, which is a reasonable design and an unreasonable surprise if you
were planning to flip it mid-incident. Set it before the process starts.

---

## `store` is not set, which is not the same as `False`

`ModelSettings.store` defaults to `None`, and the SDK omits the parameter
from the request when it is `None` — verified in
`agents/models/openai_responses.py`, which wraps it in `_non_null_or_omit`.

So whether your request and response are retained server-side is decided by
the API default and your account settings. Neither of those is in your
repository, and neither will send you a changelog.

```python
ModelSettings(store=False)   # regulated traffic
ModelSettings(store=True)    # you want the Responses API to hold state
```

The audit does not care which you pick. It objects to nobody having picked:
an explicit value is a decision a reviewer can read, `None` is a decision
somebody else makes for you.

---

## What hardening actually looks like

```python
from agents import ModelSettings, RunConfig, set_trace_processors
from agent_service.tracing import EstateTraceProcessor

set_trace_processors([EstateTraceProcessor(my_sink)])   # REPLACES the default

run_config = RunConfig(
    workflow_name="inbox-triage",          # so traces are attributable
    group_id=f"tenant:{tenant_id}",        # so they are filterable and deletable
    trace_include_sensitive_data=False,    # spans keep shape, lose payloads
    model_settings=ModelSettings(store=False),
)
```

> **`set_trace_processors` replaces. `add_trace_processor` appends.**
> Reach for `add_` and the default OpenAI exporter keeps running alongside
> yours. Your spans arrive in your sink, everything looks correct, and the
> copy continues. There is a test pinning this distinction because it is
> exactly the sort of thing a refactor "simplifies".

You lose less debuggability than you expect. Span structure — shape,
timing, token counts, errors, which tool was called and how long it took —
is most of what anyone actually reads. The payloads are what you reach for
on the tenth investigation, and by then you want them in your own store
anyway.

---

## What the audit cannot see

Printed with every report, on purpose:

- **Your account's data-retention setting**, including any Zero Data
  Retention agreement. That is negotiated, not configured, and it is
  invisible from inside the process.
- **Network egress policy.** A blocked outbound route makes the tracing
  finding moot; an open one makes it real.
- **Whatever your tools do.** A tool that writes to a third-party API moves
  more data than tracing ever will, and no `RunConfig` field describes it.
- **Prompt content.** This is about the pipe, not the payload — see
  [02](02-guardrails.md).

A tool that reports its own blind spots is usable in a review. A tool that
returns `COMPLIANT` is a liability in one.

---

**Next:** [02 · Guardrails](02-guardrails.md)
