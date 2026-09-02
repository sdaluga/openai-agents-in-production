# Example 03 — Two customers, one conversation id

```bash
python examples/03-sessions/tenant_isolation.py
```

No API key. No network. Under a second.

The `Session` protocol takes one opaque string. This runs through what
happens when that string arrives in a request body.

**1 · One optional argument, two different bugs.**

```
(a) SQLiteSession("1")                    → worker 2 sees: []
(b) SQLiteSession("1", db_path=...)       → globex sees: ['acme: our Q3 target is Northwind']
```

Without `db_path` you get amnesia across replicas, which presents as "the
agent keeps forgetting" and gets diagnosed as a model problem. With it you
get sharing — which production needs — and the session id becomes the entire
authorisation model. Neither signature suggests you have chosen.

**2 · The tenant as a field on the type**, not a concatenation at the call
site: `acme/1` and `globex/1`.

**3 · Path traversal**: `"../globex/1"` resolves to
`acme/___globex_1-d63ca09f`. Both halves are sanitised independently, with
a hash suffix so `a/b` and `a:b` don't collapse into one conversation.

**4 · What `limit` means.** `get_items(limit=3)` returns `['turn 6', 'turn
7', 'turn 8']`. The wrong implementation returns turns 1–3 — a perfectly
coherent view of the start of the conversation, forever, with no error and
no failing test.

**5 · Retention on read**, not only on write. The next request is exactly
when an expired turn would have gone to a model.

## A note on section 1

It originally claimed the in-memory case leaked across tenants. The
example's own self-check caught that — it doesn't — and the section is
better for showing both failure modes instead.

**Read next:** [docs/03 · Sessions and tenancy](../../docs/03-sessions-and-tenancy.md)
