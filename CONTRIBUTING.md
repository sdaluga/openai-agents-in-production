# Contributing

## The bar

Every control in this repository is a claim, and every claim is enforced by
something that fails when the claim stops being true. A PR that adds a
control adds two things:

1. **A test named for the production incident it prevents.**
   `test_decontaminate_works` tells a future reader nothing about whether it
   is safe to delete. `test_omitting_a_constrained_argument_does_not_bypass_the_constraint`
   tells them exactly.

2. **A mutant in `tools/mutate.py`** that breaks the control, with a
   one-line `prevents` describing what goes wrong in production.

Then run it:

```bash
pytest
python tools/mutate.py
```

A mutant that **SURVIVES** means the control is a comment that happens to
execute. A mutant that comes back **INVALID** broke import rather than
failing a test, which demonstrates nothing about coverage — rewrite it so it
is valid Python that changes behaviour.

## Claims about the SDK

Anything this repository asserts about `openai-agents` goes in
`tests/test_sdk_contract.py`, verified against the installed package rather
than quoted from documentation. If you find a claim in the docs or a
docstring that has no test behind it, that is a bug worth filing on its own.

When a pinned behaviour changes upstream, the fix is usually to **rewrite
the prose**, not to loosen the test. The failure message on each of those
tests says which prose to go and fix.

## Things especially worth contributing

- **SDK behaviours this gets wrong.** Highest value. Bring the test.
- **Posture findings.** Anything a `RunConfig`, `ModelSettings` or
  environment can cause that a reviewer would want to know about.
- **Redaction shapes that leak in practice.** Real ones from real
  pipelines, with a `specificity` that keeps them from eating each other.
- **Session backends.** Not full clients — the docs map Postgres, DynamoDB
  and Redis in a few lines each, and a corrected mapping is worth more than
  a reference implementation somebody will copy.

## Things deliberately out of scope

- **A prompt-injection classifier.** The repository's position is that this
  is not solvable by pattern matching, and a better pattern list would
  undercut the argument rather than strengthen it.
- **A full DLP or NER pass.** The redactor is explicitly a first pass and
  names the products you hand off to.
- **Anything that makes a check report `COMPLIANT`.** The blind-spot list is
  printed with every report on purpose.

## Style

- Comments explain **why**, not what. If a line needs a comment saying what
  it does, rename something instead.
- Docstrings on anything with a non-obvious failure mode, and they should
  name the failure.
- `ruff check src/ tests/ examples/` before pushing.
