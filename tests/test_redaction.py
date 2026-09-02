"""
Tests for in-flight redaction.

The theme running through this file: a redactor is only useful if you can
trust its output completely, so most of these tests are about the ways a
redactor can be *partially* right — which is the same as being wrong while
looking correct.
"""

from __future__ import annotations

import re

from agent_service.redaction import DEFAULT_RULES, Redactor, Rule


def R(**kw) -> Redactor:
    # A fixed key so placeholders are reproducible in assertions.
    return Redactor(key="test-key-not-a-secret", **kw)


class TestPartialRedactionIsTheRealFailure:
    def test_a_card_number_is_removed_whole(self):
        out = R().redact_text("card 4111111111111111 on file")
        assert not re.search(r"\d{4}", out), out
        assert "<card:" in out

    def test_a_less_specific_rule_cannot_eat_the_front_of_a_more_specific_match(self):
        """The bug that `Rule.specificity` exists to prevent, reproduced.

        The default rule set no longer contains an overlapping pair — that is
        what specificity is *for* — so demonstrating the hazard needs the
        overlap constructed deliberately. This is the shape the original bug
        had: a generic digit-run rule matched the leading digits of a card,
        replaced them, and left the tail sitting in the clear beside a
        placeholder.

        That output is worse than no redaction, because it looks handled.
        Nobody re-reads a field that already has a `<...>` in it.
        """
        overlapping = (
            Rule("digits", re.compile(r"\d{6}"), specificity=1),
            Rule("card", re.compile(r"\b(?:\d[ -]*?){13,19}\b"), specificity=70),
        )
        out = Redactor(overlapping, key="k").redact_text("card 4111111111111111 on file")
        assert "<card:" in out
        # Strip placeholders before looking for survivors: the hex digest
        # legitimately contains digits, and asserting against the raw string
        # would fail for a reason that has nothing to do with the property.
        survivors = re.sub(r"<[a-z_]+:[0-9a-f]+>", "", out)
        assert not re.search(r"\d", survivors), out
        assert "<digits:" not in out

    def test_an_email_inside_a_sentence_leaves_the_sentence_readable(self):
        """Redaction that destroys context gets switched off.

        The whole trade is: keep enough for an operator to work with, remove
        the value. A redactor that returns "<<<REDACTED>>>" for the entire
        message is technically safe and practically useless.
        """
        out = R().redact_text("Please forward this to sam@acme.com by Friday.")
        assert out.startswith("Please forward this to ")
        assert out.endswith(" by Friday.")
        assert "sam@acme.com" not in out

    def test_a_placeholder_is_not_itself_redactable(self):
        """Claimed in `redact_text`'s docstring, so it is asserted here.

        If a later rule could match inside a placeholder, the output would
        depend on rule order in ways nobody could reason about, and
        redacting twice would not equal redacting once.
        """
        red = R()
        once = red.redact_text("sam@acme.com 555-123-4567 4111111111111111")
        twice = red.redact_text(once)
        assert once == twice


class TestStability:
    def test_the_same_value_gets_the_same_placeholder(self):
        """This is what makes a redacted trace followable.

        Without it you cannot tell whether the address in turn 1 is the
        address in turn 6, and support loses the only thing redacted
        telemetry was still good for.
        """
        red = R()
        out = red.redact_text("from sam@acme.com; reply to sam@acme.com")
        tokens = re.findall(r"<email:[0-9a-f]+>", out)
        assert len(tokens) == 2
        assert tokens[0] == tokens[1]

    def test_case_and_whitespace_do_not_split_one_person_into_two(self):
        red = R()
        assert red.token("email", "Sam@Acme.com ") == red.token("email", "sam@acme.com")

    def test_different_values_get_different_placeholders(self):
        red = R()
        assert red.token("email", "a@x.com") != red.token("email", "b@x.com")

    def test_a_configured_key_is_stable_across_instances(self):
        """Two replicas must agree, or cross-request correlation dies."""
        assert R().token("email", "a@x.com") == R().token("email", "a@x.com")

    def test_an_unconfigured_key_degrades_to_LESS_linkability_not_more(self):
        """The safe direction for a misconfiguration.

        A deployment that forgot to set REDACTION_KEY gets per-process
        placeholders: less useful, never less safe. The inverse default — a
        hardcoded key — would silently make placeholders correlatable across
        every deployment on earth.
        """
        a, b = Redactor(), Redactor()
        assert a.key_is_ephemeral and b.key_is_ephemeral
        assert a.token("email", "x@y.com") != b.token("email", "x@y.com")

    def test_the_degraded_mode_is_visible_to_a_health_check(self):
        assert Redactor(key="configured").key_is_ephemeral is False


class TestWhatItCatches:
    def test_secrets_that_have_no_business_in_a_prompt(self):
        red = R()
        for secret, label in [
            ("sk-abcdefghij0123456789", "openai_key"),
            ("AKIAIOSFODNN7EXAMPLE", "aws_key"),
            ("ghp_abcdefghijklmnopqrstuvwxyz0123456789", "github_token"),
        ]:
            out = red.redact_text(f"here you go: {secret}")
            assert secret not in out
            assert f"<{label}:" in out

    def test_a_private_key_block_is_removed_whole(self):
        """Not line by line. A key with its middle redacted is still a key
        that somebody will try, and the header alone tells an attacker what
        they found."""
        blob = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEA1234567890\nabcdefghij\n"
            "-----END RSA PRIVATE KEY-----"
        )
        out = R().redact_text(f"config:\n{blob}\ndone")
        assert "MIIEowIBAAKCAQEA" not in out
        assert "BEGIN RSA PRIVATE KEY" not in out
        assert out.startswith("config:") and out.endswith("done")

    def test_an_authorization_header_value(self):
        out = R().redact_text("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.abcdefghijklmnop")
        assert "eyJhbGci" not in out


class TestWhatItDoesNotCatchAndSaysSo:
    def test_a_persons_name_is_not_detected(self):
        """Asserted, not apologised for.

        This test exists so that nobody reads the module and assumes
        coverage it does not have. If somebody later adds NER, this test
        should be *deleted* along with the paragraph in the docstring — not
        quietly left failing.
        """
        out = R().redact_text("The account holder is Margaret Ellison.")
        assert "Margaret Ellison" in out

    def test_a_street_address_is_not_detected(self):
        out = R().redact_text("Ship to 41 Bramford Lane, Holton.")
        assert "Bramford Lane" in out


class TestStructures:
    def test_nested_dicts_and_lists_are_walked(self):
        out = R().redact({"a": ["sam@acme.com"], "b": {"c": "call 555-123-4567"}})
        assert "sam@acme.com" not in str(out)
        assert "555" not in str(out)

    def test_numbers_and_none_pass_through_untouched(self):
        """Token counts must survive redaction.

        A redactor that stringifies and mangles numeric telemetry destroys
        the part of a trace that was safe all along, and the cost lands on
        whoever is trying to explain the bill.
        """
        out = R().redact({"tokens": 1450, "ok": True, "err": None, "cost": 0.42})
        assert out == {"tokens": 1450, "ok": True, "err": None, "cost": 0.42}

    def test_dict_keys_are_preserved_so_the_shape_is_still_readable(self):
        out = R().redact({"customer_email": "sam@acme.com"})
        assert list(out) == ["customer_email"]

    def test_absurd_nesting_fails_closed_instead_of_crashing_the_request(self):
        """The redactor sits on the hot path.

        A hostile or merely silly structure must not raise, and — the part
        that matters — must not fall through unredacted. Returning a marker
        is the only outcome that is both safe and honest.
        """
        deep: object = "sam@acme.com"
        for _ in range(40):
            deep = [deep]
        out = R().redact(deep)
        assert "sam@acme.com" not in str(out)
        assert "too-deep" in str(out)


class TestFindings:
    def test_findings_report_without_transforming(self):
        found = R().findings("sam@acme.com and sk-abcdefghij0123456789")
        labels = {label for label, _ in found}
        assert "email" in labels and "openai_key" in labels

    def test_a_clean_string_reports_nothing(self):
        assert R().findings("the invoice is attached") == ()


class TestConfiguration:
    def test_a_two_character_digest_is_allowed_and_one_is_not(self):
        """Below two characters the placeholder collides constantly and
        starts implying that two different people are one person — which is
        worse than no linkability at all."""
        Redactor(key="k", digest_chars=2)
        try:
            Redactor(key="k", digest_chars=1)
        except ValueError:
            pass
        else:  # pragma: no cover
            raise AssertionError("digest_chars=1 should be rejected")

    def test_custom_rules_run_in_specificity_order(self):
        rules = (
            Rule("generic", re.compile(r"\d+"), specificity=1),
            Rule("account", re.compile(r"ACC-\d+"), specificity=99),
        )
        out = Redactor(rules, key="k").redact_text("ref ACC-4471 today")
        assert "<account:" in out
        assert "ACC-" not in out

    def test_the_default_rules_are_ordered_deterministically(self):
        """Same input, same output, run after run.

        Sorting a list of equal-specificity rules non-deterministically would
        make redacted output differ between processes, and diffing two traces
        would stop working.
        """
        a = Redactor(DEFAULT_RULES, key="k").redact_text("sam@acme.com 4111111111111111")
        b = Redactor(DEFAULT_RULES, key="k").redact_text("sam@acme.com 4111111111111111")
        assert a == b


class TestEmptyAndEdgeInputs:
    def test_an_empty_string_is_returned_unchanged(self):
        assert R().redact_text("") == ""

    def test_text_with_no_matches_is_returned_byte_for_byte(self):
        text = "Quarterly review moved to Thursday."
        assert R().redact_text(text) == text
