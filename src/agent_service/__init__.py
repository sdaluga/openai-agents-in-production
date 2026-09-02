"""
agent_service — the parts of an OpenAI Agents SDK deployment that have to be
right whether or not the agent is.

Nothing in this package calls a model. That is not an omission; it is the
design. The layers that fail silently in production — where your data goes,
what your tools will accept, whose conversation you just loaded, what your
traces contain — are all decidable without inference, and making them
decidable without inference is what makes them cheap enough to test properly.

The one module that does wire a real agent, `service.py`, imports the SDK
lazily and is the only thing here that needs an API key.
"""

from .guardrails import (
    Segment,
    ToolPolicy,
    Trust,
    Verdict,
    check_egress,
    check_injection,
    check_tool_call,
)
from .posture import (
    OPENAI_TRACES_ENDPOINT,
    Finding,
    Posture,
    Severity,
    audit,
    render,
)
from .redaction import DEFAULT_RULES, Redactor, Rule
from .session_store import (
    MemoryBackend,
    RetentionPolicy,
    ScopedSession,
    SessionKey,
)
from .tracing import CollectingSink, EstateTraceProcessor, SpanRecord

__all__ = [
    # posture
    "audit",
    "render",
    "Posture",
    "Finding",
    "Severity",
    "OPENAI_TRACES_ENDPOINT",
    # redaction
    "Redactor",
    "Rule",
    "DEFAULT_RULES",
    # guardrails
    "Trust",
    "Segment",
    "Verdict",
    "check_injection",
    "check_egress",
    "check_tool_call",
    "ToolPolicy",
    # sessions
    "SessionKey",
    "ScopedSession",
    "MemoryBackend",
    "RetentionPolicy",
    # tracing
    "EstateTraceProcessor",
    "CollectingSink",
    "SpanRecord",
]

__version__ = "0.1.0"
