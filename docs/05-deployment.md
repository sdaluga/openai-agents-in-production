# 05 · Deployment

What is left once the agent works.

---

## The gate runs at construction, not per request

```python
service = TriageService(..., strict=True)   # raises PostureError
```

A service that starts and then refuses every request is an outage with
extra steps. A service that refuses to start is a **failed deploy**, which
is a thing your organisation already knows how to handle — it rolls back,
it pages the person who deployed it, and it does so before any customer
traffic arrives.

The audit is also the same answer every time, so running it per request
spends microseconds that belong to a user.

`strict=False` is a real escape hatch, not a trap door: some teams have
decided OpenAI's trace UI is fine for their workload, and forcing them to
delete the audit to get it would lose the finding entirely. With
`strict=False` the service starts and `service.posture` stays populated, so
the decision is still visible from a health endpoint. **A control you can
disable but not hide** is one that survives contact with a deadline.

---

## Configuration, in the order it bites

```bash
# Set before the process starts. The SDK caches this on first use and
# ignores later changes — you cannot flip it mid-incident.
OPENAI_AGENTS_DISABLE_TRACING=true        # "true" or "1". NOT "yes".

# Correlates redaction placeholders across replicas. From your secret
# store, never from source. Unset degrades safely (per-process key) and
# logs a warning, because the symptom is otherwise invisible.
REDACTION_KEY=<32+ random bytes>

# The inference credential. Note that it is ALSO the trace-export
# credential, which is the fact that makes the default exporter a
# security question rather than a preference.
OPENAI_API_KEY=<...>
```

---

## Concurrency and what is safe to share

| | Scope | Why |
|---|---|---|
| `TriageService` | one per process | the audit, the agent and the processor are all process-level |
| `Redactor` | one per process | the key must be stable; rebuilding per request breaks correlation |
| `EstateTraceProcessor` | one per process | installed globally by `set_trace_processors` |
| `RunConfig` | shared, **never mutated** | see below |
| `ScopedSession` | one per request | it is a handle, not a connection |

The `RunConfig` one has teeth. It is shared across concurrent requests, and
setting `group_id` on it per turn is a race that surfaces as **traces
attributed to the wrong customer** — a bug and a disclosure at the same
time. Use `dataclasses.replace`:

```python
run_config = dataclasses.replace(self._run_config, group_id=f"tenant:{tenant_id}")
```

There is a test for this, because the mutation version is shorter and reads
fine.

---

## Sessions in a multi-replica deployment

The default `MemoryBackend` is named to be unattractive in a review, on
purpose. `SQLiteSession` reads like a database and behaves like a
dictionary; `MemoryBackend` reads like a dictionary, which is the honest
advertisement.

For anything with more than one replica you need a shared backend — four
methods, a few dozen lines, mapped in
[03](03-sessions-and-tenancy.md#backends). Two things to get right:

- **Batch writes are atomic.** A partial write leaves a user message with no
  assistant reply.
- **The tenant is the partition.** Leading column, partition key, key
  prefix — whatever your store calls it, so that a mis-scoped query returns
  nothing rather than somebody else's conversation.

And **run the retention batch job.** Read-side enforcement makes the policy
*true*; it does not reclaim storage, and a table that only grows is a
different incident arriving on a slower timer.

---

## The `Runner.run` failure path

```python
result = await Runner.run(agent, input, session=session, run_config=run_config)
```

Note what `service.py` does **not** do: wrap this in a `try/except` that
returns a friendly string. Swallowing an inference failure into a 200 is how
a broken agent runs for a week. Let the caller see the exception and decide
— it is the layer that knows whether this request had a user waiting on it.

`max_turns` defaults to **10**, which is a cost ceiling as much as a
correctness one. A tool loop that never converges costs ten model calls per
request before anyone notices. Set it to what your workflow actually needs.

---

## What a review actually asks

Not "is it secure". These, roughly in this order:

**Where does the data go?**
Two flows, not one: inference, and traces. Name the second explicitly, then
`examples/01` prints the answer for your configuration.

**Who can read what?**
The storage key, with the tenant as its leading component. Show that a
client-supplied conversation id cannot reach another prefix — the traversal
case in `examples/03` is that demonstration.

**What is retained, and for how long?**
`store`, `prompt_cache_retention`, your `RetentionPolicy`, and — named as a
blind spot rather than assumed away — your account's retention setting.

**What stops the agent doing something expensive?**
`ToolPolicy`, and the honest framing that this is the control while the
injection tripwire is triage. Reviewers respect the distinction; they have
seen the other kind of answer.

**How do you know any of this is still true?**
`pytest`, then `python tools/mutate.py`. The second is the one that lands:
every control is broken deliberately, and the suite is shown going red.

**What does this not cover?**
Have an answer ready. The blind-spot list is printed with every report for
this reason — the fastest way to lose a review is to claim coverage you do
not have and be found out inside it.

---

## Deployment checklist

```
[ ] OPENAI_AGENTS_DISABLE_TRACING set before process start — "true" or "1"
[ ] a trace processor you own installed with set_ (not add_)
[ ] trace_include_sensitive_data=False
[ ] workflow_name set to this service
[ ] group_id set per tenant
[ ] no identifiers in trace_metadata
[ ] ModelSettings(store=...) set explicitly, either way
[ ] REDACTION_KEY from a secret store
[ ] session backend shared across replicas, tenant as partition
[ ] retention policy set AND the reclamation job scheduled
[ ] max_turns set to what the workflow needs
[ ] tool allowlist matches the tools actually attached to the agent
[ ] argument bounds on every tool that spends money or sends anything
[ ] the posture gate runs at construction with strict=True
```

The last line of `examples/01` is the machine-readable version of the first
seven.

---

**Back to:** [README](../README.md) · [01 · What the defaults do](01-what-the-defaults-do.md)
