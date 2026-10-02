"""Local snapshot storage.

Each scan writes two files so later phases can re-derive the graph from
raw data without calling Azure again:
    <home>/snapshots/<stamp>.raw.json    exactly what Resource Graph returned
    <home>/snapshots/<stamp>.graph.json  the built graph
and <home>/latest.json points to the newest stamp.

Default home is ~/.neuromap (override with NEUROMAP_HOME). These files
describe your network in detail, so treat the folder as sensitive.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .graph import InfraGraph, build_graph


def home() -> Path:
    h = Path(os.environ.get("NEUROMAP_HOME", Path.home() / ".neuromap"))
    (h / "snapshots").mkdir(parents=True, exist_ok=True)
    (h / "maps").mkdir(parents=True, exist_ok=True)
    return h


def save(raw: dict) -> tuple[str, InfraGraph]:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    g = build_graph(raw)
    snap = home() / "snapshots"
    (snap / f"{stamp}.raw.json").write_text(json.dumps(raw), encoding="utf-8")
    (snap / f"{stamp}.graph.json").write_text(json.dumps(g.to_dict()), encoding="utf-8")
    (home() / "latest.json").write_text(json.dumps({"stamp": stamp}), encoding="utf-8")
    return stamp, g


def latest_stamp() -> str | None:
    p = home() / "latest.json"
    return json.loads(p.read_text(encoding="utf-8"))["stamp"] if p.exists() else None


def load(stamp: str | None = None) -> tuple[str, InfraGraph] | None:
    stamp = stamp or latest_stamp()
    if not stamp:
        return None
    p = home() / "snapshots" / f"{stamp}.graph.json"
    if not p.exists():
        return None
    g = InfraGraph.from_dict(json.loads(p.read_text(encoding="utf-8")))
    if g.meta.get("builder_version") != __version__ and (home() / "snapshots" / f"{stamp}.raw.json").exists():
        # Graph written by a different NeuroMap version: re-derive it from the raw scan so code
        # and data always match (no Azure calls).
        return rebuild(stamp)
    return stamp, g


def graph_mtime(stamp: str | None) -> float | None:
    p = home() / "snapshots" / f"{stamp}.graph.json" if stamp else None
    return p.stat().st_mtime if p and p.exists() else None


def list_snapshots() -> list[str]:
    return sorted(p.name.split(".")[0] for p in (home() / "snapshots").glob("*.graph.json"))


def rebuild(stamp: str | None = None) -> tuple[str, InfraGraph]:
    """Re-derive the graph from a saved raw snapshot (no Azure calls). Use after upgrading."""
    stamp = stamp or latest_stamp()
    if not stamp:
        raise FileNotFoundError("No snapshot yet. Run a scan first.")
    raw = json.loads((home() / "snapshots" / f"{stamp}.raw.json").read_text(encoding="utf-8"))
    g = build_graph(raw)
    (home() / "snapshots" / f"{stamp}.graph.json").write_text(json.dumps(g.to_dict()), encoding="utf-8")
    return stamp, g
