# Contributing

## The precision contract

Every change must keep these true (see README):

1. Every fact records its source (`arg` or `arm <api-version>`).
2. Every verdict lists the exact fields it came from (`because`).
3. Missing or unreadable data is `unknown` with a reason, never a guess.
4. A documented Azure default may be applied only when it is written into `because` or `notes`.
5. Nothing is inferred from names, tags or naming conventions.
6. No secrets are read.

## Workflow

```bash
python -m venv .venv
# Windows: .venv\Scripts\python.exe   Linux/macOS: .venv/bin/python
python -m pip install -e .
git config core.hooksPath .githooks    # leak guard before every commit
python -m neuromap selftest            # must stay 100% green
```

## Adding or fixing an evaluator

1. Reproduce the case in a fixture (`fixture_v2.py` / `fixture_v3.py`) with **synthetic** data
   only: subscription `00000000-1111-2222-3333-444444444444`, documentation IP ranges
   (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), invented names.
2. Add a check in `selftest.py` that pins the exact verdict and `because` text.
3. Never paste real scan output into a fixture, issue or PR. Describe the shape of the data instead.
