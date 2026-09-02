# 02 · Guardrails

Start with the claim this repository refuses to make:

> **It does not detect prompt injection.** Nothing does, reliably.

Injection is a natural-language problem with an adversary on the other end.
A pattern list is a speed bump that the adversary reads before they write.
Any library telling you otherwise is selling you the feeling of a control.

What *does* hold is narrower, and it is three separate things that get
confused with each other:

| | Mechanism | What it is |
|---|---|---|
| 1 | Provenance-scoped tripwire | **triage** — a signal, not a decision |
| 2 | Tool policy | **the control** — the only one that survives an adversary |
| 3 | Egress check | **the net** — last cheap moment |

```bash
python examples/02-guardrails/run_guardrails.py
```

Four emails. The fourth carries an injection the tripwire does not catch,
and the refund still does not happen.

---

## 1 · Provenance is the only decidable part

Most systems collapse "what the user typed" and "what the system fetched"
into one bucket called *input*. That collapse is why injection filters are
simultaneously too noisy to keep on and too weak to rely on.

```python
class Trust(Enum):
    OPERATOR   # your system prompt. Trusted absolutely.
    USER       # what the human typed. Trusted to ASK, not to authorise.
    UNTRUSTED  # email bodies, web pages, tool results, other tenants' records.
```

Instructions addressed to the agent are only suspicious in `UNTRUSTED`
content. People say *"ignore the previous instructions, I meant Q3"*
constantly, because they change their minds. A filter that treats that as
an attack generates noise until somebody switches it off — and then it is
not there for the case that mattered.

The same sentence inside a fetched email body has no innocent reading.

```
2 · The obvious injection
  tripwire   TRIPPED   injection:override,role-reassign
             email body: Ignore all previous instructions

3 · The user changes their mind
  tripwire   clean
```

Two identical sentences. Two different verdicts. That is the whole idea,
and it is decidable — you know where your bytes came from — where "is this
an attack?" is not.

### What the patterns catch

Override phrasings, role reassignment, system-prompt extraction, fake turn
boundaries (`<|im_start|>system` in an email body has no legitimate use),
and coercion toward acting silently. That is the unsophisticated majority
and nothing else, which is exactly the claim made for it.

Notice what is **not** on the list: anything about the *content* of a
request. "Send money to X" is not a pattern here, because deciding whether
that is legitimate is the tool policy's job, and unlike the tripwire the
tool policy can actually decide it.

### And it will be evaded

There is a test asserting that a reworded injection gets through:

```
tests/test_guardrails.py::TestTheTripwireDoesNotClaimToBeAControl::
    test_a_trivially_reworded_injection_is_missed
```

That is the honest form of a security claim: the boundary of the mechanism
lives in the test suite, where a reader meets it, rather than in a caveat
they skim.

---

## 2 · The tool policy is the control

The least interesting code in the repository, which is roughly the ratio
you should expect from security work.

```python
POLICY = ToolPolicy(
    allowed_tools=frozenset({"lookup_ticket", "issue_refund"}),
    argument_checks={
        "issue_refund": {"amount_cents": lambda v: type(v) is int and 0 < v <= 50_000}
    },
    revoke_when_suspicious=frozenset({"issue_refund"}),
)
```

Three properties, each with a test named for what it prevents:

**It is an allowlist.** A denylist protects you from the tools you thought
of. When somebody adds `send_email` next quarter, an allowlist fails closed
and a denylist fails open, and nobody is watching either way.

**A missing argument is a rejection, not a skipped check.** If absent means
"nothing to validate", the way past every bound in your policy is to omit
the argument.

**Unparseable input is a rejection.** "I cannot judge it, so I will allow
it" is how a control becomes a formality. This one fails closed.

And the demonstration that matters:

```
4 · The injection the tripwire misses
  tripwire   clean
  tool call  issue_refund({'amount_cents': 900000})
  policy     REFUSED   tool:argument-rejected
```

The check never read the email. It never asked whether the model had been
persuaded. It would have refused just as flatly if the request had been
sincere and the number a typo.

**Filtering prompts scales with how clever the attacker is. Bounding what a
tool will accept does not.**

---

## 3 · Suspicion downgrades privilege

This is where the tripwire earns its place. It cannot decide whether an
attack happened — so it does not try. It withholds the tools that can cause
harm while the answer is unclear:

```
2 · The obvious injection
  issue_refund   REFUSED   tool:revoked-while-suspicious
  lookup_ticket  allowed
```

The turn still completes. The agent can still answer. It just cannot act.

That distinction is what makes a heuristic usable: failing the whole request
on a signal that is merely suggestive is how heuristics get removed.

---

## 4 · The egress net

Whatever happened in the middle, a secret in the final output is a finding.

The default block list is **secrets and financial identifiers, not all
PII**. A support agent answering "what address do you have for me?" is
supposed to say an address. Block that and the team carves out exceptions
until the guardrail means nothing.

Blocking the categories that have no legitimate reason to appear in a
generated answer is a check that stays switched on. That is the entire
selection criterion.

Two details:

- **Withhold, do not redact-and-send.** A model that emitted a secret once
  will do it again, and you want that loud.
- **The evidence is a placeholder, not the value.** An alert quoting the key
  it found has moved that key into your ticketing system, your alert
  history, and somebody's phone.

```
egress check  BLOCKED  egress:openai_key
evidence      <openai_key:e19d>
```

---

## Redaction, briefly

[`redaction.py`](../src/agent_service/redaction.py) backs both the egress
check and the trace processor. Three properties worth knowing:

- **Stable.** The same value produces the same placeholder, so a redacted
  trace is still followable — `<email:7f3a>` in turn 1 is the same address
  as `<email:7f3a>` in turn 6.
- **Not reversible by you.** The placeholder is a truncated HMAC. If you
  need to resolve one, hold that mapping in your own system, subject to your
  own retention rules — not in a trace that is already elsewhere.
- **Degrades safely.** With no `REDACTION_KEY` a random per-process key is
  used: placeholders stop correlating across replicas, which is *less*
  linkability, never more. The service logs a warning, because the symptom
  is otherwise invisible until you are mid-incident.

And what it misses, stated plainly and asserted in tests: **names,
addresses, account references** — anything that is PII because of what it
means rather than what it looks like. Those need a real NER or DLP pass
(Purview, Macie, Cloud DLP). This is where you hand off to one, not a reason
to skip it.

A redactor that implies completeness gets trusted, and a trusted redactor
that misses one field in ten thousand is more dangerous than no redactor at
all — because without one, nobody would have exported the payload.

---

**Next:** [03 · Sessions and tenancy](03-sessions-and-tenancy.md)
