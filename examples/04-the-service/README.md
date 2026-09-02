# Example 04 — The whole thing, assembled

```bash
python examples/04-the-service/triage_service.py          # no API key
python examples/04-the-service/triage_service.py --live   # calls a model
```

The default is a dry run. It builds the real `TriageService` — real tools,
real session store, real trace processor — and exercises everything up to
and including the decision about whether the model may be called, then
stops. That covers every line this repository is about, which is why it's
the mode CI runs.

`--live` sends one request. It needs `OPENAI_API_KEY` and costs a fraction
of a cent. It's here so the wiring is demonstrably real rather than an
elaborate mock, but nothing in the argument depends on running it.

```
tenant acme     conversation t-5512      storage key  acme/t-5512
  screening     clean
  issue_refund  REFUSED  tool:argument-rejected        ← $9,000 vs a $500 bound
  lookup_ticket allowed

tenant globex   conversation t-5512      storage key  globex/t-5512
  screening     SUSPICIOUS  injection:override,role-reassign
  issue_refund  REFUSED  tool:revoked-while-suspicious
  lookup_ticket allowed                                ← the turn can still answer
```

Both tenants sent the same conversation id. Nothing in the request handler
had to remember to keep them apart: the tenant is a field on `SessionKey`,
so the version of this code that forgets it doesn't exist.

The service **refuses to start** on a leaking posture. A failed deploy is
something organisations already handle; a service that starts and then
rejects every request is an outage with extra steps.

**Read next:** [docs/05 · Deployment](../../docs/05-deployment.md)
