# 03 · Sessions and tenancy

```bash
python examples/03-sessions/tenant_isolation.py
```

The SDK's `Session` protocol is small and good:

```python
class Session(Protocol):
    session_id: str
    session_settings: SessionSettings | None

    async def get_items(self, limit: int | None = None) -> list[TResponseInputItem]: ...
    async def add_items(self, items: list[TResponseInputItem]) -> None: ...
    async def pop_item(self) -> TResponseInputItem | None: ...
    async def clear_session(self) -> None: ...
```

Four methods, no ceremony, and a dozen implementations ship with the SDK
(`SQLiteSession`, `RedisSession`, `SQLAlchemySession`, `MongoDBSession`,
`OpenAIConversationsSession`, and a compaction wrapper).

It also takes **one opaque string**, and that turns out to matter.

---

## One argument, two different bugs

`SQLiteSession` is the one everybody starts with, and which bug you get
depends on a single optional argument that does not look like a decision:

```python
SQLiteSession("conversation-1")                       # in-process database
SQLiteSession("conversation-1", db_path="conv.db")    # shared file
```

**Without `db_path`** you get amnesia. It works perfectly in development,
works perfectly in the first container, and silently starts every
conversation from scratch the moment you run two replicas. It presents as
*"the agent keeps forgetting"* and gets diagnosed as a model problem.

**With `db_path`** you get sharing — which is what production needs, and
which makes the session id the entire authorisation model:

```
(b) SQLiteSession("1", db_path=...) — shared, as production needs
    acme writes, globex reads, both using the id their client sent
    globex sees: ['acme: our Q3 target is Northwind']
```

Neither signature suggests you have chosen between these. This section of
example 03 was originally written claiming the first case leaked, and the
example's own self-check caught the error — which is why it now shows both.

---

## The fix is a type, not vigilance

```python
@dataclass(frozen=True)
class SessionKey:
    tenant: str
    conversation: str

    @property
    def storage_key(self) -> str:
        return f"{_slug(self.tenant)}/{_slug(self.conversation)}"
```

The tenant is not concatenated in at the call site — it is a field on the
type. Every handler that builds a session by string concatenation will
eventually contain one handler that does not, and that is a code-review
problem. Making the pair a type turns it into a type error.

Two details that are load-bearing:

**The tenant is the leading component.** In Postgres it is the leading
column of the primary key; in DynamoDB it is the partition key; in Redis it
is the key prefix. A mis-scoped query returns nothing rather than somebody
else's conversation — the boundary is not expressible rather than merely
forbidden.

**Both halves are sanitised independently, with a collision suffix.**

```
acme sends conversation_id = "../globex/1"
resolved storage key: acme/___globex_1-d63ca09f
```

The suffix is not decoration. `a/b` and `a:b` both sanitise to `a_b` under
a naive implementation, and two conversations merging into one is the same
class of bug as a tenant collision arriving through a different door.

---

## The protocol's sharp edges

Each is pinned by a test that runs against **both** this store and the
SDK's `SQLiteSession`, so a divergence from either side turns the build red.

### `get_items(limit=N)` returns the *latest* N, oldest-first

The subtlest bug in this problem space. Return the first N and the agent
gets a perfectly coherent view of the beginning of the conversation,
forever:

```
8 turns stored.  get_items(limit=3) → ['turn 6', 'turn 7', 'turn 8']
the wrong implementation returns    → ['turn 1', 'turn 2', 'turn 3']
```

Both are plausible readings of "limit". One of them produces an agent that
cannot remember anything after turn three, without an error, a warning, or
a single failing test.

Get the *ordering* half wrong instead — newest-first — and the model
receives the conversation backwards, which is confusing rather than
obviously broken, and takes far longer to find.

### `pop_item()` removes from the end

It exists for correction and retry. Pop from the front and every retry
silently deletes the oldest turn, which looks like drift.

### `add_items(items)` is a batch and must be atomic

A partial write leaves a user message with no assistant reply, and the next
turn ships that to the model as though the agent had ignored somebody.

### `session_settings` is a Protocol member, not a method

```python
class MethodsOnly:
    session_id = "x"
    async def get_items(self, limit=None): ...
    async def add_items(self, items): ...
    async def pop_item(self): ...
    async def clear_session(self): ...

isinstance(MethodsOnly(), Session)   # False
```

`agents.Session` is `runtime_checkable` with a non-method member. Implement
all four documented methods, omit that one attribute, and the isinstance
check fails — with no error at construction and none at first use. One line
to fix, an afternoon to find. It has its own test, and if the SDK ever
softens it, that test tells you to delete the warning rather than leave it
as folklore.

---

## Nothing bounds growth, so something has to

The protocol has no TTL, no cap and no eviction. A long-running conversation
grows until the context call fails or the invoice does, and both arrive well
after the decision that caused them.

```python
RetentionPolicy(max_age_seconds=60 * 60 * 24 * 30, max_items=400)
```

**Enforced on read, not only on write.** Write-side eviction alone leaves an
idle conversation past its TTL fully readable on the next request — and the
next request is precisely when its contents go to a model.

**Reading does not delete.** Reclaiming storage is a batch job against the
same policy. Conflating the two puts a delete on the hot path of a read,
which is how a retention policy becomes a latency incident.

---

## Backends

The store takes a `SessionBackend` with four methods. The mapping to real
infrastructure is deliberately boring:

| | |
|---|---|
| **Postgres** | one row per item, `PRIMARY KEY (storage_key, seq)`, identity column for `seq`, `DELETE ... WHERE seq = (SELECT max(seq) ...)` for pop |
| **DynamoDB** | partition key = `storage_key`, sort key = `seq`. The tenant is in the partition key, so a cross-tenant read is not expressible |
| **Redis** | a LIST per key. `RPUSH` / `RPOP` / `LRANGE`, and the key's TTL gives you retention free — but Redis is a cache, and a conversation that vanishes mid-run because a key expired is a support ticket nobody will diagnose |

None of them ships here. A reference implementation of a Postgres client is
a liability: it will be subtly wrong about your connection pooling, and it
will be copied anyway.

---

**Next:** [04 · Observability](04-observability.md)
