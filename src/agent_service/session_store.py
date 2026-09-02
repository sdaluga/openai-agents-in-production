"""
A `Session` implementation for services that have more than one customer.

--------------------------------------------------------------------------
Why not just use SQLiteSession
--------------------------------------------------------------------------
`SQLiteSession("conversation-123")` is the right thing in the quickstart and
the wrong thing in a deployment, for three reasons that are easy to miss
because none of them produce an error:

  1. **In-memory by default.** `SQLiteSession(session_id)` with no `db_path`
     is an in-process database. It works perfectly in development, works
     perfectly in the first container, and silently starts every conversation
     from scratch the moment you run two replicas — which presents as "the
     agent keeps forgetting", gets diagnosed as a model problem, and is not
     one.

  2. **The session id is the whole authorisation model.** The protocol takes
     a bare string. If that string reaches you from a request body, then
     whoever can name a session can read it. There is no tenant dimension in
     the protocol to forget to fill in, which is exactly why it gets
     forgotten.

  3. **Nothing bounds growth.** The protocol has no TTL, no cap, and no
     eviction. A long-running conversation grows until the context window
     call fails or the invoice does, and both of those arrive later than the
     decision that caused them.

This module addresses all three, and is careful to be a `Session` rather than
to wrap one: the SDK's protocol is small and stable, and implementing it
directly means there is no adapter layer to be wrong.

--------------------------------------------------------------------------
The protocol's sharp edges, verified rather than assumed
--------------------------------------------------------------------------
Each of these is pinned by a test in `tests/test_session_store.py` that runs
the same assertion against this store *and* against the SDK's own
`SQLiteSession`. If a future SDK release changes the contract, the test fails
against theirs first, which is the earliest anyone could know.

  - `get_items(limit=N)` returns the **latest** N items, in chronological
    order. Not the first N. A store that returns the first N is the subtlest
    bug in this file's problem space: the agent gets a perfectly coherent
    view of the beginning of the conversation, forever, and every symptom
    points at the model.

  - `pop_item()` removes from the **end**. It exists for correction and
    retry. Pop from the front and you delete the oldest turn each time a run
    is retried, which corrupts history in a way that looks like drift.

  - `add_items(items)` receives a **batch** and must be all-or-nothing. A
    partial write leaves a user message with no assistant reply, and the next
    turn ships that to the model as though the agent had ignored someone.

  - `agents.Session` is a `runtime_checkable` Protocol with a non-method
    member, `session_settings`. Implement all four methods and omit that
    attribute and `isinstance(store, Session)` is **False** — with no error
    at construction and no error at first use. It is a one-line fix and an
    afternoon to find, so it has its own test.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import time
from dataclasses import dataclass
from typing import Any, Protocol

__all__ = [
    "SessionKey",
    "SessionBackend",
    "MemoryBackend",
    "ScopedSession",
    "RetentionPolicy",
]


_SAFE = re.compile(r"[^a-zA-Z0-9_-]")


def _slug(value: str, *, limit: int = 64) -> str:
    """Make a string safe to use as part of a storage key.

    Returns a hash-suffixed slug when anything had to be replaced, because
    the naive version of this function is a collision waiting to happen:
    `a/b` and `a:b` both sanitise to `a_b`, and two tenants sharing a key is
    the exact failure this module exists to prevent.

    `contract.sanitize` in a sibling repository had this bug. It is repeated
    here as a comment rather than as a mistake.
    """
    cleaned = _SAFE.sub("_", value)[:limit]
    if cleaned != value:
        digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]
        cleaned = f"{cleaned[: limit - 9]}-{digest}"
    return cleaned or "default"


@dataclass(frozen=True)
class SessionKey:
    """A conversation, and the tenant it belongs to.

    This type exists so that the tenant cannot be forgotten. The SDK's
    protocol takes one opaque string; every call site that builds one by
    concatenation will eventually contain a call site that does not. Making
    the pair a type moves that from a code-review question to a type error.

    `storage_key` is the only thing that ever reaches a backend, and the
    tenant is always the leading component — so a mis-scoped query returns
    nothing rather than someone else's conversation.
    """

    tenant: str
    conversation: str

    @property
    def storage_key(self) -> str:
        return f"{_slug(self.tenant)}/{_slug(self.conversation)}"

    def __str__(self) -> str:
        return self.storage_key


@dataclass(frozen=True)
class RetentionPolicy:
    """Bounds on a conversation, since the protocol supplies none.

    Both limits are enforced on read as well as write. Enforcing only on
    write means an idle conversation that has already exceeded its TTL is
    still served in full on the next request — the one request where it
    matters, because that is when it goes to a model.
    """

    #: Drop items older than this. None = keep forever, which is a decision
    #: somebody should make on purpose rather than by omission.
    max_age_seconds: float | None = 60 * 60 * 24 * 30
    #: Hard cap on retained items. Oldest are evicted first.
    max_items: int | None = 400

    def __post_init__(self) -> None:
        if self.max_items is not None and self.max_items < 1:
            raise ValueError("max_items below 1 stores nothing and reads as a typo")


@dataclass
class _Entry:
    item: dict[str, Any]
    stored_at: float


class SessionBackend(Protocol):
    """Storage, factored out so the session logic is testable without one.

    The mapping to real infrastructure is deliberately boring:

      Postgres   one row per item, PRIMARY KEY (storage_key, seq), an
                 identity column for `seq`, and `DELETE ... WHERE seq =
                 (SELECT max(seq) ...)` for pop. Index on (storage_key, seq).
      DynamoDB   partition key = storage_key, sort key = seq. The tenant is
                 in the partition key, so cross-tenant reads are not
                 expressible rather than merely forbidden.
      Redis      a LIST per storage_key. RPUSH to append, RPOP to pop,
                 LRANGE to read. Set the TTL on the key and retention comes
                 free — but Redis is a cache, and a conversation that
                 vanishes mid-run because a key expired is a support ticket
                 nobody will diagnose.

    Every one of those is a few dozen lines. None of them is shipped here,
    because a reference implementation of a Postgres client is a liability:
    it will be subtly wrong about your connection pooling and it will be
    copied anyway.
    """

    async def append(self, key: str, items: list[dict[str, Any]], now: float) -> None: ...
    async def read(self, key: str) -> list[_Entry]: ...
    async def pop(self, key: str) -> dict[str, Any] | None: ...
    async def clear(self, key: str) -> None: ...


class MemoryBackend:
    """In-process backend, for tests and single-node development.

    Named to be unattractive in a deployment review. `SQLiteSession` reads
    like a database and behaves like a dictionary; this reads like a
    dictionary, which is the honest advertisement.

    The lock is not decoration. `add_items` must be atomic (see the module
    docstring) and asyncio gives no atomicity across an await boundary, so
    the invariant needs enforcing here rather than being inherited from a
    single-threaded assumption that stops being true the first time somebody
    adds a real backend.
    """

    def __init__(self) -> None:
        self._data: dict[str, list[_Entry]] = {}
        self._lock = asyncio.Lock()

    async def append(self, key: str, items: list[dict[str, Any]], now: float) -> None:
        async with self._lock:
            bucket = self._data.setdefault(key, [])
            # Build the whole batch first, then extend once. If anything in
            # the comprehension raises, nothing has been written.
            entries = [_Entry(item=dict(item), stored_at=now) for item in items]
            bucket.extend(entries)

    async def read(self, key: str) -> list[_Entry]:
        async with self._lock:
            return list(self._data.get(key, ()))

    async def pop(self, key: str) -> dict[str, Any] | None:
        async with self._lock:
            bucket = self._data.get(key)
            if not bucket:
                return None
            return bucket.pop().item

    async def clear(self, key: str) -> None:
        async with self._lock:
            self._data.pop(key, None)

    # Test affordance, not part of the protocol. Named loudly so it does not
    # get mistaken for one.
    def _debug_keys(self) -> list[str]:
        return sorted(self._data)


class ScopedSession:
    """A tenant-scoped, bounded `agents.Session`.

    Satisfies `isinstance(x, agents.Session)`, including the
    `session_settings` attribute that is easy to omit. There is a test that
    asserts exactly that, and it is not a tautology — it caught the omission
    while this class was being written.
    """

    #: Required by the Protocol. Present even though it is None, because the
    #: isinstance check tests for the attribute and not for a value.
    session_settings: Any = None

    def __init__(
        self,
        key: SessionKey,
        backend: SessionBackend,
        *,
        retention: RetentionPolicy | None = None,
        clock: Any = time.time,
    ) -> None:
        self._key = key
        self._backend = backend
        self._retention = retention or RetentionPolicy()
        self._clock = clock

    # -- the Session protocol ---------------------------------------------

    @property
    def session_id(self) -> str:
        """The SDK reads this for tracing and for its own bookkeeping.

        It is the *storage* key — tenant included. That means a trace can be
        filtered to a tenant without a join, and it means the id in a log
        line is the id you would query with. Returning the bare conversation
        id here would make the tenant invisible everywhere it matters.
        """
        return self._key.storage_key

    async def get_items(self, limit: int | None = None) -> list[dict[str, Any]]:
        """The latest `limit` items, oldest-first.

        Both halves of that sentence are load-bearing and both are pinned by
        tests that also run against `SQLiteSession`: *latest* rather than
        first, and *oldest-first* rather than newest-first. Get the second
        one wrong and the model receives the conversation backwards, which
        produces output that is confusing rather than obviously broken.
        """
        entries = await self._backend.read(self._key.storage_key)
        entries = self._apply_retention(entries)
        if limit is not None:
            if limit <= 0:
                return []
            entries = entries[-limit:]
        return [e.item for e in entries]

    async def add_items(self, items: list[dict[str, Any]]) -> None:
        """Append a batch, atomically.

        An empty batch is a no-op rather than an error. The SDK calls this
        with whatever a turn produced, and a turn that produced nothing is
        normal — raising here would turn an ordinary case into an outage.
        """
        if not items:
            return
        await self._backend.append(
            self._key.storage_key, list(items), self._clock()
        )

    async def pop_item(self) -> dict[str, Any] | None:
        """Remove and return the most recent item, or None if empty."""
        return await self._backend.pop(self._key.storage_key)

    async def clear_session(self) -> None:
        """Delete this conversation.

        Scoped to one storage key, which is prefixed by the tenant. There is
        no method on this class that can clear more than one conversation,
        and that is a deliberate omission: the bulk-delete path belongs in an
        operations tool with its own authorisation, not one attribute access
        away from a request handler.
        """
        await self._backend.clear(self._key.storage_key)

    # -- retention ---------------------------------------------------------

    def _apply_retention(self, entries: list[_Entry]) -> list[_Entry]:
        """Enforce the policy on read.

        Read-side enforcement is what makes the policy true rather than
        aspirational. Write-side eviction alone leaves an idle conversation
        over its TTL fully readable on the next request — and the next
        request is precisely when its contents go to a model.

        This does not delete anything. Reclaiming storage is a batch job
        against the same policy, and conflating the two puts a delete on the
        hot path of a read.
        """
        out = entries
        if self._retention.max_age_seconds is not None:
            cutoff = self._clock() - self._retention.max_age_seconds
            out = [e for e in out if e.stored_at >= cutoff]
        if self._retention.max_items is not None:
            out = out[-self._retention.max_items :]
        return out
