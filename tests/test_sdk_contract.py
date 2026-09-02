"""
Pin every claim this repository makes about the SDK against the real package.

--------------------------------------------------------------------------
Why this file exists
--------------------------------------------------------------------------
The README, the docs and `posture.py` all assert things about the OpenAI
Agents SDK: that tracing is on by default, that spans carry payloads by
default, that the default exporter posts to a particular URL, that
`set_trace_processors` replaces while `add_trace_processor` appends.

Documentation that asserts something about a dependency is documentation that
is true on the day it was written. This file turns each of those assertions
into a test, so the day one stops being true is a red build rather than a
paragraph that quietly became a lie.

Every test here is named for the sentence it defends, and every failure
message says which prose to go and fix.

These tests need the SDK installed. They are the only tests in the suite that
do.
"""

from __future__ import annotations

import pytest

agents = pytest.importorskip("agents", reason="pins claims about the real SDK")


class TestTheDefaultsAreWhatWeSayTheyAre:
    """The three defaults the whole repository is built around."""

    def test_tracing_is_on_unless_you_turn_it_off(self):
        # README: "Tracing is ON."  posture.py: egress:default-trace-exporter
        assert agents.RunConfig().tracing_disabled is False, (
            "RunConfig.tracing_disabled is no longer False by default. The "
            "egress:default-trace-exporter finding and the README's headline "
            "claim are now wrong — fix both."
        )

    def test_spans_carry_model_payloads_unless_you_turn_it_off(self):
        # posture.py: egress:sensitive-span-payloads
        assert agents.RunConfig().trace_include_sensitive_data is True, (
            "trace_include_sensitive_data no longer defaults to True. The "
            "egress:sensitive-span-payloads finding needs rewriting."
        )

    def test_the_default_exporter_posts_to_the_url_we_quote(self):
        from agents.tracing.processors import BackendSpanExporter

        from agent_service.posture import OPENAI_TRACES_ENDPOINT

        assert BackendSpanExporter().endpoint == OPENAI_TRACES_ENDPOINT, (
            "The SDK's default trace endpoint changed. posture.py quotes it "
            "in a BLOCK finding and docs/01 quotes it in prose."
        )

    def test_the_default_exporter_authenticates_with_your_api_key(self, monkeypatch):
        """The detail that makes the finding land in a review.

        "Spans go to OpenAI" is abstract. "Spans go to OpenAI with your
        production API key in the Authorization header" is a sentence a
        security reviewer acts on.
        """
        from agents.tracing.processors import BackendSpanExporter

        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-not-a-real-key")
        assert BackendSpanExporter().api_key == "sk-test-not-a-real-key"

    def test_local_logging_is_stricter_than_the_remote_export(self):
        """The inversion — the most surprising fact in this repository.

        DONT_LOG_* default to True (local logs redacted) while
        trace_include_sensitive_data defaults to True (remote export
        verbose). If this test ever fails because the two agree, the
        posture:log-trace-inversion finding should be deleted rather than
        edited, and the README paragraph about it with it.
        """
        from agents import _debug

        assert _debug.DONT_LOG_MODEL_DATA is True
        assert _debug.DONT_LOG_TOOL_DATA is True
        assert agents.RunConfig().trace_include_sensitive_data is True


class TestTheEnvironmentVariablesWeDocument:
    """docs/01 tells operators to set these. They should exist."""

    def test_disable_tracing_env_var_is_read_lazily_and_cached_forever(
        self, monkeypatch
    ):
        """Two facts, both of which cost somebody an incident.

        The variable is not read at construction. It is read on first use and
        then cached for the life of the process, so exporting it in a running
        container — the obvious move when you discover mid-incident that
        traces are going somewhere they should not — does nothing.

        docs/01 says "set it before the process starts" because of this test,
        not because of a guess.
        """
        from agents.tracing import provider

        monkeypatch.setenv("OPENAI_AGENTS_DISABLE_TRACING", "true")
        p = provider.DefaultTraceProvider()
        assert p._env_disabled is None, (
            "The provider now reads the env var eagerly. That is an "
            "improvement, and docs/01's warning about lazy reads is stale."
        )

        p._refresh_disabled_flag()
        assert p._env_disabled is True

        # Now change it. The cached value must win.
        monkeypatch.setenv("OPENAI_AGENTS_DISABLE_TRACING", "false")
        p._refresh_disabled_flag()
        assert p._env_disabled is True, (
            "The env var is no longer cached after first read. docs/01 tells "
            "operators they cannot flip this at runtime."
        )

    def test_disable_tracing_accepts_only_true_and_1(self, monkeypatch):
        """The finding that this repository's own first draft got wrong.

        'yes' and 'on' work for TRACE_INCLUDE_SENSITIVE_DATA and do NOT work
        here. An audit that accepts the union reports tracing as disabled
        when it is running — which is the one direction a governance tool
        must never be wrong in.
        """
        from agents.tracing import provider

        for value, expected in (
            ("true", True),
            ("TRUE", True),
            ("1", True),
            ("yes", False),
            ("on", False),
            ("false", False),
        ):
            monkeypatch.setenv("OPENAI_AGENTS_DISABLE_TRACING", value)
            p = provider.DefaultTraceProvider()
            p._refresh_disabled_flag()
            assert p._env_disabled is expected, (
                f"OPENAI_AGENTS_DISABLE_TRACING={value!r} now means "
                f"{p._env_disabled}. posture._truthy_strict must match."
            )

    def test_sensitive_data_env_var_is_read(self, monkeypatch):
        from agents.run_config import _default_trace_include_sensitive_data

        monkeypatch.setenv("OPENAI_AGENTS_TRACE_INCLUDE_SENSITIVE_DATA", "false")
        assert _default_trace_include_sensitive_data() is False
        monkeypatch.setenv("OPENAI_AGENTS_TRACE_INCLUDE_SENSITIVE_DATA", "on")
        assert _default_trace_include_sensitive_data() is True


class TestSetVersusAddTraceProcessor:
    """One word, and the difference between "replaced" and "also".

    `tracing.py` warns about this in its docstring. A warning about an API is
    only worth writing down if something notices when the API changes.
    """

    def test_the_two_functions_both_exist_and_are_not_the_same(self):
        assert agents.set_trace_processors is not agents.add_trace_processor

    def test_set_replaces_and_add_appends(self):
        from agents.tracing import get_trace_provider

        provider = get_trace_provider()
        multi = provider._multi_processor

        class Noop:
            def on_trace_start(self, t): ...
            def on_trace_end(self, t): ...
            def on_span_start(self, s): ...
            def on_span_end(self, s): ...
            def force_flush(self): ...
            def shutdown(self): ...

        original = list(multi._processors)
        try:
            a, b = Noop(), Noop()
            agents.set_trace_processors([a])
            assert list(multi._processors) == [a], (
                "set_trace_processors no longer replaces. tracing.py's "
                "docstring is now wrong in the dangerous direction."
            )
            agents.add_trace_processor(b)
            assert list(multi._processors) == [a, b], (
                "add_trace_processor no longer appends."
            )
        finally:
            agents.set_trace_processors(original)


class TestTheSessionProtocol:
    """Claims made in session_store.py's docstring."""

    def test_get_items_with_a_limit_returns_the_LATEST_items(self):
        """The subtlest bug in the problem space, pinned against the SDK.

        If this ever returns the *first* N, a store built to match this
        contract is now wrong, and the symptom is an agent with a perfect
        memory of the start of the conversation and none of the rest.
        """
        import asyncio

        from agents.memory import SQLiteSession

        async def go():
            s = SQLiteSession("contract-latest")
            await s.add_items([{"role": "user", "content": f"m{i}"} for i in range(5)])
            return [i["content"] for i in await s.get_items(limit=2)]

        assert asyncio.run(go()) == ["m3", "m4"]

    def test_pop_item_removes_from_the_end(self):
        import asyncio

        from agents.memory import SQLiteSession

        async def go():
            s = SQLiteSession("contract-pop")
            await s.add_items([{"role": "user", "content": f"m{i}"} for i in range(3)])
            popped = await s.pop_item()
            rest = [i["content"] for i in await s.get_items()]
            return popped["content"], rest

        assert asyncio.run(go()) == ("m2", ["m0", "m1"])

    def test_omitting_session_settings_silently_fails_the_isinstance_check(self):
        """The afternoon-losing one.

        `agents.Session` is a runtime_checkable Protocol with a non-method
        member. Implement all four documented methods, omit that one
        attribute, and isinstance is False — with no error at construction
        and none at first use.

        This test asserts the trap still exists, so that the paragraph in
        session_store.py warning about it stays honest. If the SDK ever fixes
        it, delete the paragraph and this test together.
        """

        class MethodsOnly:
            session_id = "x"

            async def get_items(self, limit=None):
                return []

            async def add_items(self, items): ...
            async def pop_item(self):
                return None

            async def clear_session(self): ...

        assert not isinstance(MethodsOnly(), agents.Session)

        class WithTheAttribute(MethodsOnly):
            session_settings = None

        assert isinstance(WithTheAttribute(), agents.Session)


class TestModelSettingsStore:
    """posture.py claims `store=None` is omitted from the request."""

    def test_store_is_unset_by_default(self):
        assert agents.ModelSettings().store is None, (
            "ModelSettings.store now has a default. The posture:store-unset "
            "finding needs to say what that default is."
        )

    def test_our_scoped_session_satisfies_the_protocol(self):
        """The class this repository ships must pass the check above.

        Not a tautology — it failed when first written, for exactly the
        reason documented in `test_omitting_session_settings...`.
        """
        from agent_service.session_store import MemoryBackend, ScopedSession, SessionKey

        store = ScopedSession(SessionKey("acme", "c1"), MemoryBackend())
        assert isinstance(store, agents.Session)
