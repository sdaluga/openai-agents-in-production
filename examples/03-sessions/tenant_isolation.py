#!/usr/bin/env python3
"""
Example 03 — two customers, one conversation id.

    python examples/03-sessions/tenant_isolation.py

No API key. No network. Under a second.

The SDK's `Session` protocol takes one string. This example shows what
happens when that string comes from a request body and two customers both
call their conversation "1" — first with the SDK's own `SQLiteSession`,
then with a store where the tenant is part of the type.

Nothing here is a criticism of `SQLiteSession`. It does exactly what it says
and it is the right thing in a quickstart. The failure is architectural: a
protocol with no tenant dimension has no field for you to forget to fill in,
so nobody notices it is missing until the wrong conversation comes back.
"""

from __future__ import annotations

import asyncio
import tempfile

from agent_service.session_store import (
    MemoryBackend,
    RetentionPolicy,
    ScopedSession,
    SessionKey,
)

BAR = "─" * 74


def items(*contents: str) -> list[dict]:
    return [{"role": "user", "content": c} for c in contents]


def texts(rows: list[dict]) -> list[str]:
    return [r["content"] for r in rows]


async def the_naive_way(tmpdir: str) -> tuple[list[str], list[str]]:
    """Two traps, and you get exactly one of them depending on one argument.

    This section originally showed only the cross-tenant read, and the
    example's own self-check caught it: `SQLiteSession("1")` with no
    `db_path` is an in-process database, so two instances do not share at
    all. The claim was wrong.

    It turns out to be the better demonstration for having been wrong.
    Omitting `db_path` gives you the amnesia bug; supplying it gives you the
    isolation bug; and nothing in either signature suggests you have chosen
    between them.
    """
    from agents.memory import SQLiteSession

    # -- (a) no db_path: in-process. Two workers, two memories. ----------
    acme_w1 = SQLiteSession("1")
    acme_w2 = SQLiteSession("1")
    await acme_w1.add_items(items("acme: our Q3 target is Northwind"))
    amnesia = texts(await acme_w2.get_items())

    print(f"\n{BAR}\n  1 · SQLiteSession, id straight from the request\n{BAR}")
    print("  (a) SQLiteSession(\"1\")  — no db_path")
    print("      worker 1 writes, worker 2 reads the same conversation")
    print(f"      worker 2 sees: {amnesia}")
    print(
        "      Nothing shared. On one process this is invisible; on two it\n"
        "      presents as 'the agent keeps forgetting' and gets diagnosed\n"
        "      as a model problem."
    )

    # -- (b) with db_path: shared. And now the id is the whole ACL. ------
    db = f"{tmpdir}/conversations.db"
    acme = SQLiteSession("1", db_path=db)
    globex = SQLiteSession("1", db_path=db)
    await acme.add_items(items("acme: our Q3 target is Northwind"))
    leaked = texts(await globex.get_items())

    print('\n  (b) SQLiteSession("1", db_path=...) — shared, as production needs')
    print("      acme writes, globex reads, both using the id their client sent")
    print(f"      globex sees: {leaked}")
    return amnesia, leaked


async def the_scoped_way() -> tuple[list[str], list[str]]:
    backend = MemoryBackend()
    acme = ScopedSession(SessionKey("acme", "1"), backend)
    globex = ScopedSession(SessionKey("globex", "1"), backend)

    await acme.add_items(items("our Q3 acquisition target is Northwind"))
    leaked = texts(await globex.get_items())
    own = texts(await acme.get_items())

    print(f"\n{BAR}\n  2 · ScopedSession, tenant in the key\n{BAR}")
    print(f"  acme   storage key: {acme.session_id}")
    print(f"  globex storage key: {globex.session_id}")
    print(f"\n  globex sees: {leaked}")
    print(f"  acme  sees: {own}")
    return leaked, own


async def the_traversal_attempt() -> list[str]:
    backend = MemoryBackend()
    victim = ScopedSession(SessionKey("globex", "1"), backend)
    attacker = ScopedSession(SessionKey("acme", "../globex/1"), backend)

    await victim.add_items(items("globex confidential"))
    got = texts(await attacker.get_items())

    print(f"\n{BAR}\n  3 · And the obvious next thing an attacker tries\n{BAR}")
    print('  acme sends conversation_id = "../globex/1"')
    print(f"  resolved storage key: {attacker.session_id}")
    print(f"  it sees: {got}")
    print(
        "\n  The tenant is not concatenated in, it is the leading component,\n"
        "  and both halves are sanitised independently. There is no string a\n"
        "  client can send in the conversation field that reaches another\n"
        "  tenant's prefix."
    )
    return got


async def the_limit_trap() -> tuple[list[str], list[str]]:
    """The bug that presents as a model problem.

    Return the first N instead of the latest N and the agent gets a
    perfectly coherent view of the beginning of the conversation, forever.
    Every symptom points at the model: it forgets, it loops, it ignores
    what was just said. None of those are model problems.
    """
    store = ScopedSession(SessionKey("acme", "long"), MemoryBackend())
    await store.add_items(items(*[f"turn {i}" for i in range(1, 9)]))

    latest = texts(await store.get_items(limit=3))
    first_three = texts(await store.get_items())[:3]

    print(f"\n{BAR}\n  4 · What a limit means\n{BAR}")
    print(f"  8 turns stored.  get_items(limit=3) → {latest}")
    print(f"  the wrong implementation returns    → {first_three}")
    print(
        "\n  Both are plausible readings of 'limit'. One of them makes an\n"
        "  agent that cannot remember anything after turn three, and does it\n"
        "  without an error, a warning, or a single failing test."
    )
    return latest, first_three


async def retention() -> list[str]:
    now = [1_000_000.0]
    store = ScopedSession(
        SessionKey("acme", "old"),
        MemoryBackend(),
        retention=RetentionPolicy(max_age_seconds=86_400, max_items=None),
        clock=lambda: now[0],
    )
    await store.add_items(items("last month's conversation"))
    now[0] += 86_400 * 31
    await store.add_items(items("this morning"))

    live = texts(await store.get_items())

    print(f"\n{BAR}\n  5 · Retention is enforced on read\n{BAR}")
    print("  two turns stored, 31 days apart, 24h policy")
    print(f"  get_items() → {live}")
    print(
        "\n  Enforcing only on write would leave the expired turn readable on\n"
        "  the next request — and the next request is exactly when its\n"
        "  contents go to a model."
    )
    return live


async def main() -> int:
    print("\n" + "=" * 74)
    print("  Session isolation, and the four ways to lose it")
    print("=" * 74)

    with tempfile.TemporaryDirectory() as tmpdir:
        amnesia, naive = await the_naive_way(tmpdir)
    scoped_leak, scoped_own = await the_scoped_way()
    traversal = await the_traversal_attempt()
    latest, first_three = await the_limit_trap()
    live = await retention()

    print("\n" + "=" * 74)
    print(
        """
  None of this is exotic. It is the ordinary consequence of a protocol
  that takes one string, used by a handler that has one string to hand.

  The fix is not vigilance. It is making the tenant part of the type, so
  that the call site which forgets it does not compile as a thought.
"""
    )

    problems: list[str] = []
    if amnesia:
        problems.append(
            "An in-memory SQLiteSession now shares state between instances. "
            "Section 1(a)'s amnesia demonstration is gone."
        )
    if not naive:
        problems.append(
            "A file-backed SQLiteSession no longer shares state across two "
            "instances with the same id. The cross-tenant read in section "
            "1(b) is the premise of this whole example — check whether the "
            "SDK changed, then rewrite the section rather than the claim."
        )
    if scoped_leak:
        problems.append("ScopedSession leaked across tenants. This is the whole point.")
    if not scoped_own:
        problems.append("ScopedSession lost the tenant's own data.")
    if traversal:
        problems.append("A path-traversal conversation id reached another tenant.")
    if latest == first_three:
        problems.append("Section 4 no longer contrasts two behaviours.")
    if live != ["this morning"]:
        problems.append("Retention is no longer filtering the expired turn.")

    if problems:
        print("  THIS EXAMPLE HAS STOPPED DEMONSTRATING ITS POINT:\n")
        for p in problems:
            print(f"    - {p}")
        return 1

    print("  premise verified: the naive store leaked, the scoped store did not.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
