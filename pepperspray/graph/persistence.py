"""Checkpointer selection and run history.

With a ``checkpoint_db`` path, runs are persisted to SQLite so they survive a
process restart — enabling genuine pause→approve→resume and time-travel. Without
one, an in-memory saver is used (fast, non-durable).
"""

from __future__ import annotations

import sqlite3
from typing import Any

from langgraph.checkpoint.memory import MemorySaver


def get_checkpointer(checkpoint_db: str | None = None):
    """Return a durable SqliteSaver when a db path is given, else MemorySaver."""
    if not checkpoint_db:
        return MemorySaver()
    from langgraph.checkpoint.sqlite import SqliteSaver

    conn = sqlite3.connect(checkpoint_db, check_same_thread=False)
    saver = SqliteSaver(conn)
    # Create the checkpoint tables up front. It is idempotent (CREATE TABLE IF
    # NOT EXISTS); some langgraph-checkpoint-sqlite builds do not auto-setup on
    # first put/get, which would otherwise fail with "no such table".
    saver.setup()
    return saver


def list_checkpoints(graph: Any, thread_id: str, limit: int = 50) -> list[dict]:
    """Return a compact history of a thread's checkpoints (newest first)."""
    config = {"configurable": {"thread_id": thread_id}}
    out: list[dict] = []
    for snap in graph.get_state_history(config):
        if len(out) >= limit:
            break
        ckpt_id = snap.config.get("configurable", {}).get("checkpoint_id", "")
        out.append(
            {
                "checkpoint_id": ckpt_id,
                "next": list(snap.next),
                "step": snap.metadata.get("step") if snap.metadata else None,
                "completed_steps": snap.values.get("completed_steps", []),
                "findings": len(snap.values.get("findings", [])),
            }
        )
    return out
