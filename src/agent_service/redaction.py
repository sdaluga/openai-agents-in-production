"""
Redaction for data in flight.

--------------------------------------------------------------------------
The difference between this and a dataset PII scan
--------------------------------------------------------------------------
A curation scanner *reports* and lets a human decide, because the dataset is
sitting still and there is time. A redactor runs on the hot path of a live
request, and there is no human. It has to transform, it has to be fast, and
it has to be wrong in a predictable direction.

So the contract here is:

  - It **replaces**, it never drops the record. A redactor that swallows a
    span leaves you debugging blind, and a blind operator disables the
    redactor.
  - It is **stable**: the same input value produces the same placeholder
    inside one deployment, so a conversation is still followable. You can see
    that <email:7f3a> appears in turn 1 and again in turn 6 without ever
    seeing the address.
  - It is **not reversible by you**. The placeholder is a truncated HMAC,
    not an encryption. If you need to resolve a placeholder to a value, you
    hold that mapping in your own system where it is subject to your own
    retention rules — not in a trace that is already somewhere else.

--------------------------------------------------------------------------
What it will miss
--------------------------------------------------------------------------
Names. Addresses. Account references. Anything that is PII because of what it
means rather than what it looks like. Those need a real NER or DLP pass —
Microsoft Purview, AWS Macie, Google DLP — and this module is where you hand
off to one, not a reason to skip it.

This is stated plainly because the alternative is worse. A redactor that
implies completeness gets trusted, and a trusted redactor that misses one
field in ten thousand is more dangerous than no redactor at all, since
without one nobody would have exported the payload in the first place.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from re import Pattern
from typing import Any

__all__ = [
    "Rule",
    "Redactor",
    "DEFAULT_RULES",
    "redact",
]


@dataclass(frozen=True)
class Rule:
    """One pattern and the label its matches are replaced with.

    `specificity` orders the rules. Higher runs first, and it exists because
    of a bug this module had and a test now prevents: a generic
    long-digit-run rule matched the leading digits of a card number, replaced
    them, and left the last four digits sitting in the clear next to a
    placeholder — which is worse than leaving the whole number, because it
    looks redacted.

    Ordering by specificity is therefore not a nicety. It is the difference
    between a redaction and a partial redaction, and a partial redaction is
    an unredacted field with a reassuring appearance.
    """

    label: str
    pattern: Pattern[str]
    specificity: int = 0


def _p(expr: str) -> Pattern[str]:
    return re.compile(expr)


#: Shapes that leak through copy-paste, integrations and well-meaning users.
#: Every one of these has been observed arriving in a prompt from a support
#: ticket, an email body, or a pasted log line.
DEFAULT_RULES: tuple[Rule, ...] = (
    # --- secrets first: the most specific and the most expensive to leak ---
    Rule("openai_key", _p(r"\bsk-[A-Za-z0-9_-]{16,}\b"), specificity=100),
    Rule("aws_key", _p(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), specificity=100),
    Rule("github_token", _p(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), specificity=100),
    Rule(
        "private_key",
        _p(
            r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----"
            r"[\s\S]*?"
            r"-----END (?:[A-Z ]+ )?PRIVATE KEY-----"
        ),
        specificity=100,
    ),
    Rule("bearer", _p(r"\bBearer\s+[A-Za-z0-9._~+/-]{20,}=*"), specificity=95),
    # --- structured identifiers ---
    Rule(
        "email",
        _p(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        specificity=80,
    ),
    # Card before SSN before phone before "long run of digits": each of these
    # can match inside the next, and the shortest one must not win.
    Rule("card", _p(r"\b(?:\d[ -]*?){13,19}\b"), specificity=70),
    Rule("ssn", _p(r"\b\d{3}-\d{2}-\d{4}\b"), specificity=65),
    Rule(
        "phone",
        _p(r"(?<!\d)(?:\+?1[ .-]?)?\(?\d{3}\)?[ .-]?\d{3}[ .-]?\d{4}(?!\d)"),
        specificity=60,
    ),
    Rule("ipv4", _p(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), specificity=50),
    Rule("iban", _p(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"), specificity=55),
)


class Redactor:
    """Deterministic, stable, non-reversible replacement.

    Construct once per process and reuse. The key matters:

    - Pass `key` explicitly (from your secret store) and placeholders are
      stable across processes, restarts and replicas. `<email:7f3a>` in
      today's trace is the same address as `<email:7f3a>` in last week's.
      That is what makes a redacted trace usable for support.

    - Omit it and a random key is generated per process. Placeholders are
      then stable within one process and meaningless across two. That is the
      safe default — an accidental deployment without a configured key
      degrades to *less* linkability, never to more — but it is a degraded
      mode, and `key_is_ephemeral` is exposed so a health check can say so
      out loud rather than leaving you to discover it during an incident.
    """

    def __init__(
        self,
        rules: Iterable[Rule] = DEFAULT_RULES,
        *,
        key: bytes | str | None = None,
        digest_chars: int = 4,
    ) -> None:
        if key is None:
            key = os.environ.get("REDACTION_KEY")
        self.key_is_ephemeral = key is None
        if key is None:
            key = secrets.token_bytes(32)
        if isinstance(key, str):
            key = key.encode("utf-8")
        self._key = key

        if digest_chars < 2:
            raise ValueError("digest_chars below 2 collides constantly and misleads")
        self._digest_chars = digest_chars

        # Sort once, descending. Ties keep declaration order, which is stable
        # because DEFAULT_RULES is a tuple, so the same input always redacts
        # to the same output — a property one of the tests pins.
        self._rules = tuple(sorted(rules, key=lambda r: -r.specificity))

    # -- core -------------------------------------------------------------

    def token(self, label: str, value: str) -> str:
        """The placeholder for one value.

        Normalised before hashing so that `Sam@Acme.com ` and `sam@acme.com`
        share a token. Without that, case differences across turns make one
        person look like two, and the linkability the placeholder exists to
        provide quietly stops working.
        """
        normalised = value.strip().lower()
        digest = hmac.new(self._key, normalised.encode("utf-8"), hashlib.sha256)
        return f"<{label}:{digest.hexdigest()[: self._digest_chars]}>"

    def redact_text(self, text: str) -> str:
        """Replace every match in `text`.

        Runs rules in specificity order. Because each rule rewrites the
        string before the next one sees it, and a placeholder contains no
        digits beyond its hex digest and no `@`, a later generic rule cannot
        chew into an earlier specific replacement.

        That last sentence is a claim about the placeholder format, so it has
        a test: `test_a_placeholder_is_not_itself_redactable`.
        """
        if not text:
            return text
        out = text
        for rule in self._rules:
            out = rule.pattern.sub(
                lambda m, _label=rule.label: self.token(_label, m.group(0)), out
            )
        return out

    def redact(self, value: Any, *, _depth: int = 0) -> Any:
        """Walk a structure and redact every string in it.

        Depth is capped. A cyclic or absurdly nested object arriving from a
        tool result must not take the process down — the redactor sits on the
        hot path, and a redactor that can crash the request is a redactor
        somebody removes.

        At the cap the value is replaced with a marker rather than passed
        through. Failing closed is the only defensible direction here: the
        whole point of this function is that what it returns is safe to
        export.
        """
        if _depth > 12:
            return "<redacted:too-deep>"
        if isinstance(value, str):
            return self.redact_text(value)
        if isinstance(value, Mapping):
            return {k: self.redact(v, _depth=_depth + 1) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            redacted = [self.redact(v, _depth=_depth + 1) for v in value]
            return type(value)(redacted) if isinstance(value, tuple) else redacted
        # int, float, bool, None and anything exotic pass through. A number is
        # not redactable without knowing what it means, and guessing produces
        # a redactor that eats your token counts.
        return value

    def findings(self, text: str) -> tuple[tuple[str, str], ...]:
        """What would be redacted, without redacting it.

        For the guardrail path, which needs to *decide* rather than
        transform, and for tests that want to assert on detection separately
        from replacement.
        """
        found: list[tuple[str, str]] = []
        for rule in self._rules:
            for m in rule.pattern.finditer(text):
                found.append((rule.label, m.group(0)))
        return tuple(found)


#: A module-level convenience for callers that do not need a configured key.
#: Deliberately not used by anything in this package: every real call site
#: constructs its own Redactor, because the key is a deployment decision and
#: hiding it behind a default is how you end up with ephemeral keys in prod.
def redact(text: str) -> str:
    return Redactor().redact_text(text)
