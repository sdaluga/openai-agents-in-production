"""
Tests for the estate trace processor.

The first class is the important one. A trace processor runs inside the
request path, so the difference between "telemetry broke" and "the service
broke" is entirely down to whether this class can raise.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agent_service.redaction import Redactor
from agent_service.tracing import CollectingSink, EstateTraceProcessor


@dataclass
class FakeSpanData:
    type: str = "generation"
    name: str | None = "call-model"
    payload: dict[str, Any] | None = None

    def export(self) -> dict[str, Any]:
        return self.payload if self.payload is not None else {}


@dataclass
class FakeSpan:
    trace_id: str = "trace_1"
    span_id: str | None = "span_1"
    parent_id: str | None = None
    started_at: str | None = "2026-01-01T00:00:00Z"
    ended_at: str | None = "2026-01-01T00:00:01Z"
    error: Any = None
    span_data: Any = None


def processor(**kw) -> tuple[EstateTraceProcessor, CollectingSink]:
    sink = CollectingSink()
    return EstateTraceProcessor(sink, redactor=Redactor(key="k"), **kw), sink


class TestItCannotTakeTheServiceDown:
    def test_a_sink_that_raises_does_not_propagate(self):
        """The whole reason the callbacks are wrapped.

        A logging backend having a bad afternoon must not become an
        availability incident, and it will always be your busiest day when
        the unusual span shows up.
        """

        def angry_sink(record):
            raise RuntimeError("the log shipper is down")

        p = EstateTraceProcessor(angry_sink)
        p.on_span_end(FakeSpan(span_data=FakeSpanData()))  # must not raise
        assert p.failures == 1

    def test_a_span_object_with_no_recognisable_fields_still_produces_a_record(self):
        """Degrade, do not drop.

        An object the processor does not understand still gets a record with
        whatever could be read. Dropping it would make an SDK change look
        like a traffic drop, and a traffic drop is the one signal an
        on-call engineer reacts to hardest and most wrongly.
        """
        p, sink = processor()
        p.on_span_end(object())
        assert p.failures == 0
        assert len(sink.records) == 1
        assert sink.records[0].trace_id == ""
        assert sink.records[0].data == {}

    def test_span_data_that_raises_on_export_does_not_propagate(self):
        class Hostile:
            type = "x"

            def export(self):
                raise ValueError("nope")

        p, _ = processor()
        p.on_span_end(FakeSpan(span_data=Hostile()))
        assert p.failures == 1

    def test_failures_are_counted_so_degradation_is_visible(self):
        """Silence is not the same as success.

        Without a counter, a processor that is swallowing every span looks
        exactly like a quiet system, and nobody investigates a quiet system.
        """

        def angry_sink(record):
            raise RuntimeError("still down")

        p = EstateTraceProcessor(angry_sink)
        for _ in range(3):
            p.on_span_end(FakeSpan(span_data=FakeSpanData()))
        assert p.failures == 3


class TestPayloadsAreDroppedByDefault:
    def test_prompt_text_does_not_reach_the_sink(self):
        """The processor must not ship the opposite of its own advice.

        `posture.py` raises a BLOCK finding for exported payloads. A
        processor that exported payloads by default would make that advice
        something the repository itself ignores.
        """
        p, sink = processor()
        p.on_span_end(
            FakeSpan(
                span_data=FakeSpanData(payload={"input": "the customer's full message"})
            )
        )
        assert "full message" not in str(sink.records[0].data)

    def test_the_SHAPE_of_the_payload_survives(self):
        """A dropped key and an empty input look identical.

        Telling those apart is most of what span-reading is for, so the
        payload is replaced rather than deleted.
        """
        p, sink = processor()
        p.on_span_end(
            FakeSpan(span_data=FakeSpanData(payload={"input": "1234567890"}))
        )
        assert sink.records[0].data["input"] == "<text:10chars>"

    def test_an_absent_payload_is_distinguishable_from_an_empty_one(self):
        p, sink = processor()
        p.on_span_end(FakeSpan(span_data=FakeSpanData(payload={"input": None})))
        assert sink.records[0].data["input"] == "<absent>"

    def test_non_payload_fields_are_kept_intact(self):
        """Model name, token counts, timings — the parts that are safe and
        are the reason you wanted traces at all."""
        p, sink = processor()
        p.on_span_end(
            FakeSpan(
                span_data=FakeSpanData(
                    payload={"model": "gpt-5-nano", "usage": {"input_tokens": 812}}
                )
            )
        )
        assert sink.records[0].data["model"] == "gpt-5-nano"
        assert sink.records[0].data["usage"]["input_tokens"] == 812

    def test_opting_in_to_payloads_still_redacts_them(self):
        """`include_payloads=True` is a legitimate choice for a sink inside
        your own boundary. It is not a choice to ship raw secrets."""
        p, sink = processor(include_payloads=True)
        p.on_span_end(
            FakeSpan(
                span_data=FakeSpanData(
                    payload={"input": "my key is sk-abcdefghij0123456789"}
                )
            )
        )
        data = str(sink.records[0].data)
        assert "sk-abcdefghij" not in data
        assert "my key is" in data


class TestErrors:
    def test_an_error_message_is_redacted(self):
        """The most common way a secret reaches a log.

        An exception whose message quotes the request body is a leak with a
        stack trace attached, and it bypasses every payload control because
        it is not a payload.
        """
        p, sink = processor()
        p.on_span_end(
            FakeSpan(
                span_data=FakeSpanData(),
                error={"message": "auth failed for sam@acme.com"},
            )
        )
        assert "sam@acme.com" not in str(sink.records[0].error)
        assert "auth failed" in str(sink.records[0].error)

    def test_a_non_dict_error_is_still_captured(self):
        p, sink = processor()
        p.on_span_end(FakeSpan(span_data=FakeSpanData(), error=ValueError("bad input")))
        assert "bad input" in str(sink.records[0].error)


class TestStartEvents:
    def test_start_events_are_emitted_so_a_hang_is_visible(self):
        """A span that never ends only exists in the start event.

        That is precisely the signal you want when something is stuck, and
        dropping start events to halve the volume throws it away.
        """
        p, sink = processor()
        p.on_span_start(FakeSpan(span_data=FakeSpanData()))
        assert len(sink.records) == 1

    def test_start_events_carry_no_payload_at_all(self):
        p, sink = processor()
        p.on_span_start(
            FakeSpan(span_data=FakeSpanData(payload={"input": "secret prompt"}))
        )
        assert sink.records[0].data == {}


class TestTheSink:
    def test_the_collector_is_bounded(self):
        """An unbounded collector is a slow test here and an outage
        anywhere else."""
        sink = CollectingSink(max_records=5)
        for i in range(8):
            sink(f"record-{i}")  # type: ignore[arg-type]
        assert len(sink.records) == 5
        assert sink.dropped == 3

    def test_it_drops_the_OLDEST_when_full(self):
        """The newest spans describe whatever is currently going wrong."""
        sink = CollectingSink(max_records=2)
        for i in range(4):
            sink(f"record-{i}")  # type: ignore[arg-type]
        assert sink.records == ["record-2", "record-3"]


class TestItDoesNotDependOnTheSDK:
    def test_the_module_imports_with_no_agents_package(self, monkeypatch):
        """A team's log-shipping code should not need an agent framework.

        This is why `EstateTraceProcessor` does not subclass
        `agents.TracingProcessor` — the SDK checks structurally, so
        inheritance buys nothing and costs the dependency.
        """
        import ast
        import pathlib

        import agent_service.tracing as mod

        source = pathlib.Path(mod.__file__).read_text()
        tree = ast.parse(source)
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])

        assert "agents" not in imported, (
            "agent_service.tracing now imports the SDK. The sink contract is "
            "supposed to be writable by a team that has not installed an "
            "agent framework."
        )
