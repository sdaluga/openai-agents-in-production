#!/usr/bin/env python3
"""
Break each control, one at a time, and confirm the suite notices.

--------------------------------------------------------------------------
Why this is a script and not a paragraph
--------------------------------------------------------------------------
"Well tested" is a claim anyone can make about anything. The falsifiable
version is: *if I remove this line, does the suite go red, and how loudly?*

A control whose removal changes nothing is not a control. It is a comment
that happens to execute. This script finds those.

Run it:

    python tools/mutate.py            # all mutants
    python tools/mutate.py --list     # what it will try
    python tools/mutate.py -k egress  # just the ones matching

Each mutant is a literal string substitution against a source file, applied
to a temporary copy of the tree. Nothing is written to your working
directory, and a mutant whose `before` text is not found is reported as
STALE rather than silently skipped — a mutation suite that quietly stops
mutating is the same failure mode it exists to catch.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


@dataclass(frozen=True)
class Mutant:
    name: str
    file: str
    before: str
    after: str
    #: Prose describing the production failure this control prevents. Printed
    #: with the result so the report reads as an argument rather than a
    #: checklist.
    prevents: str


MUTANTS: tuple[Mutant, ...] = (
    # ---------------------------------------------------------------- posture
    Mutant(
        "posture: the default exporter finding is removed",
        "src/agent_service/posture.py",
        "if tracing_on and not has_custom_processor:",
        "if False:",
        "a service exporting every prompt to a third party passes the gate",
    ),
    Mutant(
        "posture: payload exposure is no longer reported",
        "src/agent_service/posture.py",
        "if tracing_on and include_sensitive:",
        "if False:",
        "traces carry prompts and completions and the audit says nothing",
    ),
    Mutant(
        "posture: env parsing goes back to one permissive parser",
        "src/agent_service/posture.py",
        'env_disabled = _truthy_strict(env.get("OPENAI_AGENTS_DISABLE_TRACING"), False)',
        'env_disabled = _truthy_loose(env.get("OPENAI_AGENTS_DISABLE_TRACING"), False)',
        "DISABLE_TRACING=yes is reported as disabled while tracing runs",
    ),
    Mutant(
        "posture: an unreadable config is treated as safe",
        "src/agent_service/posture.py",
        "tracing_on = True  # assume the dangerous case",
        "tracing_on = False",
        "an SDK rename turns the audit into a silent all-clear",
    ),
    Mutant(
        "posture: store=None stops being reported",
        "src/agent_service/posture.py",
        "if store is _missing or store is None:",
        "if False:",
        "server-side retention is decided by an account setting nobody read",
    ),
    Mutant(
        "posture: PII in trace metadata downgraded to a warning",
        "src/agent_service/posture.py",
        'code="tenancy:pii-in-trace-metadata",\n                    severity=Severity.BLOCK,',
        'code="tenancy:pii-in-trace-metadata",\n                    severity=Severity.WARN,',
        "an email address ships with every span and the gate still passes",
    ),
    Mutant(
        "posture: blind spots stop being printed",
        "src/agent_service/posture.py",
        'lines.append("  This audit cannot see:")',
        'lines.append("")',
        "a clean report reads as a clean bill of health",
    ),
    # -------------------------------------------------------------- redaction
    Mutant(
        "redaction: rules stop being ordered by specificity",
        "src/agent_service/redaction.py",
        "key=lambda r: -r.specificity",
        "key=lambda r: r.specificity",
        "a card number keeps its last four digits beside a placeholder",
    ),
    Mutant(
        "redaction: values are not normalised before hashing",
        "src/agent_service/redaction.py",
        "normalised = value.strip().lower()",
        "normalised = value",
        "one person appears as two across turns and correlation breaks",
    ),
    Mutant(
        "redaction: deep structures fall through instead of failing closed",
        "src/agent_service/redaction.py",
        'return "<redacted:too-deep>"',
        "return value",
        "a nested payload is exported unredacted",
    ),
    Mutant(
        "redaction: an unconfigured key becomes a constant",
        "src/agent_service/redaction.py",
        "key = secrets.token_bytes(32)",
        'key = b"default-key"',
        "placeholders become correlatable across every deployment",
    ),
    # ------------------------------------------------------------- guardrails
    Mutant(
        "guardrails: the tripwire scans every segment, not just untrusted ones",
        "src/agent_service/guardrails.py",
        "if seg.trust is not Trust.UNTRUSTED:\n            continue",
        "if False:\n            continue",
        "users get blocked for changing their minds; the filter gets removed",
    ),
    Mutant(
        "guardrails: the tool allowlist is removed",
        "src/agent_service/guardrails.py",
        "if tool_name not in policy.allowed_tools:",
        "if False:",
        "a tool added next quarter runs without ever entering the policy",
    ),
    Mutant(
        "guardrails: a missing argument skips its own check",
        "src/agent_service/guardrails.py",
        "if arg_name not in arguments:",
        "if False and arg_name not in arguments:",
        "every bound in the policy is bypassed by omitting the argument",
    ),
    Mutant(
        "guardrails: unparseable arguments are allowed through",
        "src/agent_service/guardrails.py",
        "except json.JSONDecodeError:",
        "except json.JSONDecodeError if False else ():",
        "a control that cannot read its input approves it",
    ),
    Mutant(
        "guardrails: a raising predicate counts as a pass",
        "src/agent_service/guardrails.py",
        "            ok = False",
        "            ok = True",
        "hostile input that crashes a check becomes input that passes it",
    ),
    Mutant(
        "guardrails: privilege is not downgraded on suspicion",
        "src/agent_service/guardrails.py",
        "if suspicious and tool_name in policy.revoke_when_suspicious:",
        "if False:",
        "the tripwire fires and the agent acts on the injected instruction anyway",
    ),
    Mutant(
        "guardrails: egress evidence quotes the secret it found",
        "src/agent_service/guardrails.py",
        "evidence=tuple(red.token(label, value) for label, value in bad),",
        "evidence=tuple(value for label, value in bad),",
        "the leaked key is copied into your alerting stack",
    ),
    # ---------------------------------------------------------- session store
    Mutant(
        "sessions: a limit returns the FIRST items instead of the latest",
        "src/agent_service/session_store.py",
        "entries = entries[-limit:]",
        "entries = entries[:limit]",
        "the agent sees the start of the conversation forever and looks broken",
    ),
    Mutant(
        "sessions: a limit of zero returns everything",
        "src/agent_service/session_store.py",
        "if limit <= 0:\n                return []",
        "if False:\n                return []",
        "a caller asking for no history is handed all of it",
    ),
    Mutant(
        "sessions: the sanitiser drops its collision suffix",
        "src/agent_service/session_store.py",
        "cleaned = f\"{cleaned[: limit - 9]}-{digest}\"",
        "cleaned = cleaned",
        "two conversations that sanitise alike merge into one",
    ),
    Mutant(
        "sessions: the tenant leaves the storage key",
        "src/agent_service/session_store.py",
        'return f"{_slug(self.tenant)}/{_slug(self.conversation)}"',
        "return _slug(self.conversation)",
        "two customers using conversation id '1' read each other's history",
    ),
    Mutant(
        "sessions: retention is not enforced on read",
        "src/agent_service/session_store.py",
        "entries = self._apply_retention(entries)",
        "entries = entries",
        "an expired conversation is sent to a model on the next request",
    ),
    Mutant(
        "sessions: stored items are not copied",
        "src/agent_service/session_store.py",
        "entries = [_Entry(item=dict(item), stored_at=now) for item in items]",
        "entries = [_Entry(item=item, stored_at=now) for item in items]",
        "a caller mutates history it already handed over",
    ),
    Mutant(
        "sessions: the protocol attribute is dropped",
        "src/agent_service/session_store.py",
        "    session_settings: Any = None\n",
        "\n",
        "isinstance(store, Session) is False with no error anywhere",
    ),
    # ----------------------------------------------------------- tracing
    Mutant(
        "tracing: the processor stops swallowing exceptions",
        "src/agent_service/tracing.py",
        "        except Exception:  # noqa: BLE001 - see the module docstring",
        "        except () :",
        "a log-shipper outage becomes a service outage",
    ),
    Mutant(
        "tracing: payloads are included by default",
        "src/agent_service/tracing.py",
        "        include_payloads: bool = False,",
        "        include_payloads: bool = True,",
        "the processor ships the exact thing posture.py raises a BLOCK for",
    ),
    Mutant(
        "tracing: errors are no longer redacted",
        "src/agent_service/tracing.py",
        "            error = self._redactor.redact(",
        "            error = (",
        "a secret quoted in an exception message reaches the sink",
    ),
    Mutant(
        "tracing: dropped payloads leave no trace of their shape",
        "src/agent_service/tracing.py",
        "            out[key] = _shape_of(value)",
        "            pass",
        "an absent input and an empty input become indistinguishable",
    ),
    Mutant(
        "tracing: failures stop being counted",
        "src/agent_service/tracing.py",
        "                self._failures += 1",
        "                pass",
        "telemetry degrades silently and reads as a calm system",
    ),
)


def run_suite(tree: Path) -> tuple[int, str]:
    proc = subprocess.run(
        # `-o addopts=` clears the project's own `-q` from pyproject.toml.
        # Without it this call's `-q` becomes the second one, pytest reads
        # that as `-qq`, and `-qq` suppresses the final count line — which
        # made the first version of this script report every mutant as
        # killed by "0 tests". A mutation runner that miscounts is worse
        # than none, because its output is what you quote in a README.
        [
            sys.executable,
            "-m",
            "pytest",
            "-o",
            "addopts=",
            "-q",
            "--no-header",
            "-p",
            "no:cacheprovider",
        ],
        cwd=tree,
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin:/usr/local/bin", "PYTHONPATH": str(tree / "src")},
    )
    return proc.returncode, proc.stdout + proc.stderr


def summarise(output: str) -> tuple[int, int, str]:
    """(failed, errored, the summary line).

    Errors are counted separately from failures on purpose. A mutant that
    breaks *import* makes the suite exit non-zero without any test having
    made a judgement — it proves the file is syntactically load-bearing,
    which is not a claim worth making. The first version of this script
    counted those as kills, and reported 30/30 while several mutants had
    never reached a test.
    """
    lines = output.splitlines()
    # Count the short-summary lines directly rather than parsing the tally.
    # These are stable across pytest's verbosity settings; the tally line is
    # not, which is what went wrong the first time.
    failed = sum(1 for line in lines if line.startswith("FAILED "))
    errored = sum(1 for line in lines if line.startswith("ERROR "))

    summary = ""
    for line in reversed(lines):
        stripped = line.strip("= ").strip()
        if any(w in stripped for w in ("failed", "error", "passed")) and stripped[:1].isdigit():
            summary = stripped
            break
    if not summary:
        summary = f"{failed} failed, {errored} errors"
    return failed, errored, summary


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", action="store_true")
    ap.add_argument("-k", dest="filter", default="")
    args = ap.parse_args()

    selected = [m for m in MUTANTS if args.filter.lower() in m.name.lower()]

    if args.list:
        for m in selected:
            print(f"  {m.name}\n      prevents: {m.prevents}")
        return 0

    print(f"\n{len(selected)} mutants\n")
    survivors: list[Mutant] = []
    stale: list[Mutant] = []
    invalid: list[Mutant] = []

    for m in selected:
        with tempfile.TemporaryDirectory() as tmp:
            tree = Path(tmp) / "repo"
            shutil.copytree(
                ROOT,
                tree,
                ignore=shutil.ignore_patterns(
                    ".git", "__pycache__", "*.egg-info", ".pytest_cache"
                ),
            )
            target = tree / m.file
            source = target.read_text()
            if m.before not in source:
                stale.append(m)
                print(f"  STALE     {m.name}")
                print("            the text this mutant edits no longer exists")
                continue
            target.write_text(source.replace(m.before, m.after, 1))

            code, output = run_suite(tree)
            failed, errored, summary = summarise(output)
            if code == 0:
                survivors.append(m)
                print(f"  SURVIVED  {m.name}")
            elif failed == 0 and errored:
                # Not a kill. The mutant broke the module before any test
                # could judge it, so it demonstrates nothing about coverage.
                invalid.append(m)
                print(f"  INVALID   {m.name}")
                print(f"            the edit broke import ({summary}); rewrite it")
            else:
                print(
                    f"  killed    {m.name}  "
                    f"({failed} test{'s' if failed != 1 else ''} fail)"
                )
            print(f"            prevents: {m.prevents}")

    print()
    if stale:
        print(f"{len(stale)} STALE — the mutation suite has drifted from the code.")
    if invalid:
        print(f"{len(invalid)} INVALID — these broke import instead of failing a test:")
        for m in invalid:
            print(f"  - {m.name}")
    if survivors:
        print(f"{len(survivors)} SURVIVED. Each is a line nothing enforces:")
        for m in survivors:
            print(f"  - {m.name}")
    if survivors or stale or invalid:
        return 1
    print(f"All {len(selected)} mutants killed by a failing test.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
