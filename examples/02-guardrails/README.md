# Example 02 — The tripwire misses, and the refund still doesn't happen

```bash
python examples/02-guardrails/run_guardrails.py
```

No API key. No network. Under a second.

Four support emails, three checks.

```
1 · An ordinary refund request
  tripwire   clean            policy  allowed

2 · The obvious injection
  tripwire   TRIPPED          policy  REFUSED  tool:revoked-while-suspicious

3 · The user changes their mind
  tripwire   clean            policy  allowed

4 · The injection the tripwire misses
  tripwire   clean            policy  REFUSED  tool:argument-rejected
```

**Case 3** is why provenance matters: the same sentence that trips in an
email body is benign from the user, who is allowed to change their mind. A
filter that blocks case 3 gets switched off, and then it isn't there for
case 2.

**Case 4** is the argument. No override phrasing, no role reassignment — a
polite English sentence that happens to be an instruction. The tripwire
finds nothing, correctly. The $9,000 refund is refused anyway, by a bound on
`amount_cents` that never read the email and never asked whether the model
had been persuaded.

> Filtering prompts scales with how clever the attacker is.
> Bounding what a tool will accept does not.

## And on the way out

```
egress check  BLOCKED  egress:openai_key
evidence      <openai_key:e19d>
```

The evidence is a placeholder. An alert that quotes the key it found has
moved that key into your ticketing system, your alert history, and
somebody's phone.

An ordinary reply containing an email address is **allowed** — deliberately.
A support agent answering "what address do you have?" is supposed to say an
address, and a guardrail that blocks it gets exceptions carved into it until
it means nothing.

**Read next:** [docs/02 · Guardrails](../../docs/02-guardrails.md)
