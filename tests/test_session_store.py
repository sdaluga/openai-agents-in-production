"""
Tests for the tenant-scoped session store.

Several of these assert the same property against both this store and the
SDK's `SQLiteSession`. That is on purpose: the value of matching the SDK's
contract is only real if something notices when the two diverge, and the
divergence could come from either side.
"""

from __future__ import annotations

import pytest

from agent_service.session_store import (
    MemoryBackend,
    RetentionPolicy,
    ScopedSession,
    SessionKey,
)


def items(*contents: str) -> list[dict]:
    return [{"role": "user", "content": c} for c in contents]


def store(tenant="acme", conversation="c1", backend=None, **kw) -> ScopedSession:
    return ScopedSession(SessionKey(tenant, conversation), backend or MemoryBackend(), **kw)


class TestTenantIsolation:
    async def test_two_tenants_using_the_same_conversation_id_do_not_share_history(self):
        """The failure this whole type exists to make impossible.

        Conversation ids come from clients. If two customers both call
        theirs "1", and the store keys on that alone, then customer B reads
        customer A's conversation — and it presents as the agent knowing
        things it should not, which is diagnosed as hallucination.
        """
        backend = MemoryBackend()
        a = store("acme", "1", backend)
        b = store("globex", "1", backend)

        await a.add_items(items("acme secret"))
        assert await b.get_items() == []
        assert [i["content"] for i in await a.get_items()] == ["acme secret"]

    async def test_the_tenant_is_the_leading_component_of_the_storage_key(self):
        """So a mis-scoped query returns nothing rather than somebody else.

        Prefix-ordering is not cosmetic. In every backend named in the
        module docstring, the leading component is the partition — which
        makes a cross-tenant read unexpressible rather than merely
        forbidden.
        """
        assert SessionKey("acme", "c1").storage_key.startswith("acme/")

    async def test_a_hostile_conversation_id_cannot_escape_its_tenant(self):
        """`"../globex/1"` must not become globex's conversation."""
        backend = MemoryBackend()
        attacker = store("acme", "../globex/1", backend)
        victim = store("globex", "1", backend)

        await victim.add_items(items("globex data"))
        assert await attacker.get_items() == []

    async def test_two_ids_that_sanitise_to_the_same_string_stay_distinct(self):
        """`a/b` and `a:b` both become `a_b` under a naive sanitiser.

        Two conversations collapsing into one is the same class of bug as a
        tenant collision, arriving through a different door. The hash suffix
        is what keeps them apart, and this test is why the suffix exists.
        """
        backend = MemoryBackend()
        one = store("acme", "a/b", backend)
        two = store("acme", "a:b", backend)

        await one.add_items(items("first"))
        await two.add_items(items("second"))

        assert [i["content"] for i in await one.get_items()] == ["first"]
        assert [i["content"] for i in await two.get_items()] == ["second"]

    async def test_the_session_id_the_sdk_sees_carries_the_tenant(self):
        """So traces and log lines are filterable without a join."""
        assert store("acme", "c1").session_id == "acme/c1"

    async def test_clearing_one_conversation_leaves_the_tenants_others_alone(self):
        backend = MemoryBackend()
        one, two = store("acme", "c1", backend), store("acme", "c2", backend)
        await one.add_items(items("x"))
        await two.add_items(items("y"))
        await one.clear_session()
        assert await one.get_items() == []
        assert len(await two.get_items()) == 1


class TestTheProtocolContract:
    """Each of these also runs against SQLiteSession in test_sdk_contract.py."""

    async def test_a_limit_returns_the_LATEST_items_not_the_first(self):
        """The subtlest bug in this problem space.

        Return the first N and the agent gets a perfectly coherent view of
        the start of the conversation, forever. Every symptom points at the
        model: it "forgets", it "loops", it "ignores recent context". None of
        those are model problems.
        """
        s = store()
        await s.add_items(items("m0", "m1", "m2", "m3", "m4"))
        assert [i["content"] for i in await s.get_items(limit=2)] == ["m3", "m4"]

    async def test_items_come_back_oldest_first(self):
        """The other half. Newest-first produces output that is confusing
        rather than obviously broken, which takes far longer to find."""
        s = store()
        await s.add_items(items("m0", "m1", "m2"))
        assert [i["content"] for i in await s.get_items()] == ["m0", "m1", "m2"]

    async def test_pop_removes_from_the_end(self):
        """Pop is for correction and retry.

        Pop from the front and every retry silently deletes the oldest turn,
        which looks like drift and is not.
        """
        s = store()
        await s.add_items(items("m0", "m1", "m2"))
        assert (await s.pop_item())["content"] == "m2"
        assert [i["content"] for i in await s.get_items()] == ["m0", "m1"]

    async def test_popping_an_empty_session_returns_none_rather_than_raising(self):
        assert await store().pop_item() is None

    async def test_an_empty_batch_is_a_no_op_rather_than_an_error(self):
        """A turn that produced nothing is normal. Raising here would turn an
        ordinary case into an outage."""
        s = store()
        await s.add_items([])
        assert await s.get_items() == []

    async def test_a_limit_of_zero_returns_nothing_rather_than_everything(self):
        """`entries[-0:]` is the whole list. A slice-based implementation
        that does not special-case zero returns the entire conversation for
        a caller that asked for none of it."""
        s = store()
        await s.add_items(items("m0", "m1"))
        assert await s.get_items(limit=0) == []

    async def test_stored_items_are_copied_so_a_caller_cannot_mutate_history(self):
        """The caller still holds a reference to the dict it passed in."""
        s = store()
        original = [{"role": "user", "content": "as sent"}]
        await s.add_items(original)
        original[0]["content"] = "tampered"
        assert (await s.get_items())[0]["content"] == "as sent"


class TestRetention:
    async def test_a_conversation_stops_growing_without_bound(self):
        """The protocol supplies no cap. Something has to.

        Unbounded growth ends as a context-window failure or an invoice, and
        both arrive long after the decision that caused them.
        """
        s = store(retention=RetentionPolicy(max_items=3, max_age_seconds=None))
        await s.add_items(items("m0", "m1", "m2", "m3", "m4"))
        assert [i["content"] for i in await s.get_items()] == ["m2", "m3", "m4"]

    async def test_expiry_is_enforced_on_READ_not_only_on_write(self):
        """Write-side eviction alone leaves a stale conversation fully
        readable on the next request — and the next request is exactly when
        its contents go to a model."""
        now = [1000.0]
        s = store(
            retention=RetentionPolicy(max_age_seconds=60, max_items=None),
            clock=lambda: now[0],
        )
        await s.add_items(items("old"))
        now[0] += 30
        await s.add_items(items("recent"))

        now[0] += 40  # "old" is now 70s old, "recent" is 40s
        assert [i["content"] for i in await s.get_items()] == ["recent"]

    async def test_retention_applies_before_the_limit_slice(self):
        """Otherwise `get_items(limit=5)` can return four live items and one
        expired one, and the expired one is invisible in the result."""
        now = [1000.0]
        s = store(
            retention=RetentionPolicy(max_age_seconds=60, max_items=None),
            clock=lambda: now[0],
        )
        await s.add_items(items("old"))
        now[0] += 100
        await s.add_items(items("new"))
        assert [i["content"] for i in await s.get_items(limit=5)] == ["new"]

    async def test_retention_does_not_delete_anything_on_the_read_path(self):
        """Reclaiming storage is a batch job.

        Conflating the two puts a delete on the hot path of a read, which is
        how a retention policy becomes a latency incident.
        """
        now = [1000.0]
        backend = MemoryBackend()
        s = store(
            backend=backend,
            retention=RetentionPolicy(max_age_seconds=60, max_items=None),
            clock=lambda: now[0],
        )
        await s.add_items(items("old"))
        now[0] += 100
        assert await s.get_items() == []
        assert len(await backend.read("acme/c1")) == 1

    async def test_a_max_items_of_zero_is_rejected_at_construction(self):
        """It stores nothing and reads as a typo, so it should not be
        silently honoured as a policy."""
        with pytest.raises(ValueError):
            RetentionPolicy(max_items=0)

    async def test_the_default_policy_is_bounded(self):
        """A default of "keep forever" would make the module's own advice
        optional, and defaults are what actually ship."""
        p = RetentionPolicy()
        assert p.max_items is not None
        assert p.max_age_seconds is not None


class TestAtomicity:
    async def test_a_batch_is_written_all_or_nothing(self):
        """A partial write leaves a user message with no assistant reply, and
        the next turn ships that to the model as though the agent had
        ignored somebody.
        """

        # Stands in for the real failure: the second INSERT of a batch
        # failing against a database. Reproducing that faithfully needs a
        # database; reproducing the *property* needs an item that raises
        # partway through the write, which is this.
        class ExplodingItem:
            def keys(self):
                raise RuntimeError("boom")

        backend = MemoryBackend()
        s = store(backend=backend)
        await s.add_items(items("first"))

        with pytest.raises(RuntimeError):
            await s.add_items([{"role": "user", "content": "ok"}, ExplodingItem()])

        assert [i["content"] for i in await s.get_items()] == ["first"]
