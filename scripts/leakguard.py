"""Fail if anything that looks like real tenant data would be committed.

Checks every tracked file (or every file, outside git) for:
  1. /subscriptions/<guid> other than the synthetic fixture subscription
  2. any word from a local, never-committed `.leakguard` file (one per line,
     e.g. your company, tenant, resource-group or person names)
  3. e-mail addresses
  4. files that look like NeuroMap scans or maps (*.raw.json, *.graph.json,
     exported neuromap HTML), except the synthetic demo in docs/

Usage:  python scripts/leakguard.py            (exit 1 on any finding)
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_SUB = "00000000-1111-2222-3333-444444444444"
SUB_RE = re.compile(r"/subscriptions/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})", re.I)
MAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
SKIP = {"src/neuromap/static/cytoscape.min.js"}          # vendored third-party code
ALLOWED_MAPS = {"docs/demo-map.html"}                    # built from synthetic fixtures


def files() -> list[str]:
    try:
        out = subprocess.run(["git", "ls-files", "--cached", "--others", "--exclude-standard"],
                             cwd=ROOT, capture_output=True, text=True, check=True).stdout
        return [f for f in out.splitlines() if f]
    except (OSError, subprocess.CalledProcessError):
        return [str(p.relative_to(ROOT)).replace("\\", "/") for p in ROOT.rglob("*")
                if p.is_file() and ".git" not in p.parts and ".venv" not in p.parts]


def words() -> list[str]:
    p = ROOT / ".leakguard"
    if not p.exists():
        return []
    return [w.strip().lower() for w in p.read_text(encoding="utf-8").splitlines()
            if w.strip() and not w.strip().startswith("#")]


def main() -> int:
    wl, findings = words(), []
    for rel in files():
        if rel in SKIP or rel == ".leakguard":
            continue
        if rel.endswith((".raw.json", ".graph.json")):
            findings.append(f"{rel}: looks like a NeuroMap scan file")
            continue
        path = ROOT / rel
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        if rel.endswith(".html") and "Azure NeuroMap" in text and rel not in ALLOWED_MAPS:
            findings.append(f"{rel}: looks like an exported NeuroMap map")
        for n, line in enumerate(text.splitlines(), 1):
            for m in SUB_RE.finditer(line):
                if m.group(1).lower() != FIXTURE_SUB:
                    findings.append(f"{rel}:{n}: real-looking subscription id {m.group(1)}")
            for m in MAIL_RE.finditer(line):
                findings.append(f"{rel}:{n}: e-mail address {m.group(0)}")
            low = line.lower()
            for w in wl:
                if w in low:
                    findings.append(f"{rel}:{n}: contains '{w}' from .leakguard")
    if findings:
        print("leakguard: possible tenant data found, commit blocked:\n  " + "\n  ".join(findings))
        return 1
    print(f"leakguard: clean ({len(wl)} local words checked)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
