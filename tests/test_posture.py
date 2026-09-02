"""
Tests for the egress posture audit.

Named for the production situation each one prevents, not for the function
each one calls. `test_audit_works` tells a future reader nothing about
whether it is safe to delete.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agent_service.posture import (
    OPENAI_TRACES_ENDPOINT,
    Severity,
    audit,
    render,
)


# A stand-in for RunConfig. The audit is duck-typed on purpose (see its
# docstring), and testing against a fake proves that — the real thing is
# pinned separately in test_sdk_contract.py.
@dataclass
class FakeRunConfig:
    tracing_disabled: bool = False
    trace_include_sensitive_data: bool = True
    workflow_name: str = "Agent workflow"
    group_id: str | None = None
    trace_metadata: dict[str, Any] | None = None
    model_settings: Any = None


@dataclass
class FakeModelSettings:
    store: bool | None = None
    prompt_cache_retention: str | None = None


HARDENED_ENV: dict[str, str] = {}


class TestTheDefaultConfigurationIsReportedAsUnsafe:
    """The whole premise. If a bare RunConfig passes, the module is decoration."""

    def test_an_untouched_run_config_does_not_pass(self):
        posture = audit(FakeRunConfig(), environ=HARDENED_ENV)
        assert not posture.is_releasable, (
            "A default RunConfig was reported as releasable. Either the SDK "
            "defaults changed or this audit stopped working; both are "
            "reasons to stop and look."
        )

    def test_the_finding_names_the_url_data_goes_to(self):
        """A finding that says "tracing is enabled" gets waved through.

        A finding that says "spans are POSTed to <url> with your API key"
        gets escalated. The URL is the part that makes it real, so it is
        part of the assertion.
        """
        posture = audit(FakeRunConfig(), environ=HARDENED_ENV)
        finding = posture.by_code("egress:default-trace-exporter")
        assert finding is not None
        assert OPENAI_TRACES_ENDPOINT in finding.subject

    def test_payload_exposure_is_reported_separately_from_the_pipe(self):
        """Two findings, because they have two different remedies.

        Turning tracing off and keeping tracing without payloads are
        different decisions with different costs, and collapsing them into
        one finding forces the reader into the more expensive one.
        """
        posture = audit(FakeRunConfig(), environ=HARDENED_ENV)
        assert posture.by_code("egress:default-trace-exporter") is not None
        assert posture.by_code("egress:sensitive-span-payloads") is not None


class TestHardeningActuallyClearsTheFindings:
    """A gate that cannot be satisfied is a gate that gets bypassed."""

    def test_disabling_tracing_clears_both_egress_findings(self):
        posture = audit(
            FakeRunConfig(tracing_disabled=True), environ=HARDENED_ENV
        )
        assert posture.by_code("egress:default-trace-exporter") is None
        assert posture.by_code("egress:sensitive-span-payloads") is None

    def test_a_custom_processor_clears_the_exporter_finding(self):
        """Keeping tracing is a legitimate answer.

        The finding is "your spans go to a third party", not "you have
        tracing". Installing a processor you own is the remedy the finding
        recommends, so it has to work.
        """
        posture = audit(
            FakeRunConfig(),
            environ=HARDENED_ENV,
            trace_processors=[object()],
        )
        assert posture.by_code("egress:default-trace-exporter") is None

    def test_a_fully_hardened_config_is_releasable(self):
        posture = audit(
            FakeRunConfig(
                tracing_disabled=True,
                trace_include_sensitive_data=False,
                workflow_name="inbox-triage",
                group_id="tenant:acme",
            ),
            model_settings=FakeModelSettings(store=False),
            environ=HARDENED_ENV,
            tenant_id="acme",
        )
        assert posture.is_releasable
        assert posture.findings == (), render(posture)


class TestTheEnvironmentIsReadTheWayTheRuntimeReadsIt:
    """The bug this module shipped with, and the test that found it."""

    def test_disable_tracing_yes_does_not_count_as_disabled(self):
        """`OPENAI_AGENTS_DISABLE_TRACING=yes` leaves tracing ON.

        The runtime accepts only "true"/"1" (pinned in test_sdk_contract).
        An audit that accepts "yes" here would report a clean posture for a
        deployment that is exporting every prompt — the single worst
        false negative this file can produce.
        """
        posture = audit(
            FakeRunConfig(), environ={"OPENAI_AGENTS_DISABLE_TRACING": "yes"}
        )
        assert posture.by_code("egress:default-trace-exporter") is not None

    def test_a_misspelled_disable_value_is_itself_a_blocking_finding(self):
        """Somebody tried to turn tracing off and it is still on.

        Reporting only "tracing is enabled" is true and useless here — it
        reads as a configuration nobody has got to yet. Saying "you set this
        variable and it did not work" is the finding.
        """
        posture = audit(
            FakeRunConfig(), environ={"OPENAI_AGENTS_DISABLE_TRACING": "on"}
        )
        finding = posture.by_code("posture:disable-tracing-not-recognised")
        assert finding is not None
        assert finding.severity is Severity.BLOCK
        assert "'on'" in finding.subject

    def test_disable_tracing_true_is_honoured(self):
        posture = audit(
            FakeRunConfig(tracing_disabled=False),
            environ={"OPENAI_AGENTS_DISABLE_TRACING": "true"},
        )
        assert posture.by_code("egress:default-trace-exporter") is None
        assert posture.by_code("posture:disable-tracing-not-recognised") is None

    def test_sensitive_data_env_var_accepts_the_looser_spelling(self):
        """Because the runtime does. The two variables genuinely differ."""
        posture = audit(
            FakeRunConfig(),
            environ={"OPENAI_AGENTS_TRACE_INCLUDE_SENSITIVE_DATA": "on"},
        )
        # 'on' is truthy here, so payloads ARE included and the finding stands.
        assert posture.by_code("egress:sensitive-span-payloads") is not None


class TestTheLogTraceInversion:
    def test_redacted_logs_beside_a_verbose_export_is_reported(self):
        """The false sense of safety, made visible.

        An engineer who sets DONT_LOG_MODEL_DATA and stops there believes
        they have handled this. The finding exists to interrupt that belief
        at review time rather than at audit time.
        """
        posture = audit(
            FakeRunConfig(), environ={"OPENAI_AGENTS_DONT_LOG_MODEL_DATA": "true"}
        )
        assert posture.by_code("posture:log-trace-inversion") is not None

    def test_the_inversion_is_not_reported_once_the_export_is_clean(self):
        """No finding without a problem.

        A tool that reports the same warning regardless of configuration
        trains its readers to ignore it.
        """
        posture = audit(
            FakeRunConfig(trace_include_sensitive_data=False),
            environ={"OPENAI_AGENTS_DONT_LOG_MODEL_DATA": "true"},
        )
        assert posture.by_code("posture:log-trace-inversion") is None


class TestServerSideRetention:
    def test_leaving_store_unset_is_reported(self):
        posture = audit(FakeRunConfig(), model_settings=FakeModelSettings())
        assert posture.by_code("posture:store-unset") is not None

    def test_setting_store_explicitly_to_false_clears_it(self):
        posture = audit(
            FakeRunConfig(), model_settings=FakeModelSettings(store=False)
        )
        assert posture.by_code("posture:store-unset") is None

    def test_setting_store_explicitly_to_TRUE_also_clears_it(self):
        """The finding is about the decision, not the value.

        `store=True` is correct for plenty of workloads. What the audit
        objects to is nobody having chosen. If this test ever starts
        failing because somebody "improved" the check into a rule that
        store must be False, that is a change from governance to opinion.
        """
        posture = audit(
            FakeRunConfig(), model_settings=FakeModelSettings(store=True)
        )
        assert posture.by_code("posture:store-unset") is None

    def test_24h_prompt_cache_retention_is_surfaced(self):
        posture = audit(
            FakeRunConfig(),
            model_settings=FakeModelSettings(store=False, prompt_cache_retention="24h"),
        )
        assert posture.by_code("posture:cache-retention-24h") is not None


class TestTenancy:
    def test_a_tenanted_run_without_a_trace_group_is_flagged(self):
        posture = audit(
            FakeRunConfig(tracing_disabled=True), environ=HARDENED_ENV, tenant_id="acme"
        )
        assert posture.by_code("tenancy:no-trace-group") is not None

    def test_tenancy_checks_are_skipped_rather_than_guessed_when_no_tenant_is_given(
        self,
    ):
        """Silence beats a guess.

        A single-tenant service has no tenant to pass, and emitting
        tenancy findings at it would be noise that teaches people to skim.
        """
        posture = audit(FakeRunConfig(tracing_disabled=True), environ=HARDENED_ENV)
        assert posture.by_code("tenancy:no-trace-group") is None

    def test_an_email_address_in_trace_metadata_blocks(self):
        """Trace metadata is exported regardless of the sensitive-data flag.

        This is the finding people are most surprised by, because they set
        trace_include_sensitive_data=False and reasonably assumed it covered
        everything they had attached.
        """
        posture = audit(
            FakeRunConfig(
                tracing_disabled=True,
                group_id="tenant:acme",
                trace_metadata={"customer": "sam@acme.com"},
            ),
            environ=HARDENED_ENV,
            tenant_id="acme",
        )
        finding = posture.by_code("tenancy:pii-in-trace-metadata")
        assert finding is not None
        assert finding.severity is Severity.BLOCK

    def test_an_opaque_tenant_key_in_metadata_is_fine(self):
        posture = audit(
            FakeRunConfig(
                tracing_disabled=True,
                group_id="tenant:acme",
                trace_metadata={"tenant": "t_8f21a0"},
            ),
            environ=HARDENED_ENV,
            tenant_id="acme",
        )
        assert posture.by_code("tenancy:pii-in-trace-metadata") is None


class TestTheAuditFailsSafe:
    def test_an_unreadable_object_is_treated_as_the_dangerous_case(self):
        """If the audit cannot find `tracing_disabled`, it assumes tracing.

        The alternative — treating an unreadable config as safe — turns an
        SDK rename into a silent all-clear. A governance tool that goes quiet
        when it stops understanding its subject is worse than one that was
        never installed, because its silence is read as a pass.
        """

        class Unrecognisable:
            pass

        posture = audit(Unrecognisable(), environ=HARDENED_ENV)
        assert posture.by_code("posture:unknown-tracing") is not None
        assert posture.by_code("egress:default-trace-exporter") is not None
        assert not posture.is_releasable

    def test_auditing_nothing_at_all_still_reports_the_dangerous_case(self):
        posture = audit(None, environ=HARDENED_ENV)
        assert not posture.is_releasable


class TestTheReport:
    def test_blind_spots_are_printed_even_when_there_are_no_findings(self):
        """A clean report must not read as a clean bill of health.

        This is the difference between a tool that survives a review and a
        tool that gets someone in trouble during one.
        """
        posture = audit(
            FakeRunConfig(
                tracing_disabled=True,
                trace_include_sensitive_data=False,
                workflow_name="inbox-triage",
            ),
            model_settings=FakeModelSettings(store=False),
            environ=HARDENED_ENV,
        )
        # Normalise whitespace: the report is wrapped for a terminal, so a
        # phrase can legitimately straddle a line break. Asserting on the
        # raw string would make this test fail whenever the wrap width
        # changed, which is a test that tracks formatting rather than
        # meaning.
        text = " ".join(render(posture).split())
        assert posture.is_releasable
        assert "cannot see" in text
        assert "Zero Data Retention" in text

    def test_blocking_findings_are_rendered_before_warnings(self):
        posture = audit(FakeRunConfig(), environ=HARDENED_ENV)
        text = render(posture)
        assert text.index("BLOCK") < text.index("WARN")
