name: ci

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read

jobs:
  leakguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Block tenant data
        run: python scripts/leakguard.py

  selftest:
    needs: leakguard
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, windows-latest]
        python: ["3.10", "3.12", "3.14"]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python }}
      - name: Install
        run: python -m pip install .
      - name: Selftest (strict encoding, offline, no Azure)
        run: python -X warn_default_encoding -W error::EncodingWarning -m neuromap selftest
