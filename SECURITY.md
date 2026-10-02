# Security

## What this tool does and does not do

- **Read-only.** It calls Azure Resource Graph and ARM with `GET` only (plus the Resource Graph
  query endpoint). It never writes, deletes or changes Azure resources.
- **No secrets.** It never calls `listKeys`, never reads app settings, connection strings,
  connection shared keys or certificates.
- **Local data.** Scans and maps are written to `~/.neuromap` (or `NEUROMAP_HOME`) on your
  machine. They describe your network, access rules and role assignments in detail.
  **Treat that folder as sensitive.** Never attach its files to issues, chats or pull requests.
- The identity only needs **Reader**.

## Reporting a vulnerability

Please do **not** open a public issue. Use GitHub's private vulnerability reporting
(Security tab, "Report a vulnerability") with steps to reproduce. Use synthetic data only.

## Keeping tenant data out of this repo

- `.gitignore` excludes scan and map files.
- `scripts/leakguard.py` runs in CI and fails on real-looking subscription IDs, e-mail
  addresses, scan files, exported maps, and any word listed in your local `.leakguard` file.
- Enable it before every commit: `git config core.hooksPath .githooks`
