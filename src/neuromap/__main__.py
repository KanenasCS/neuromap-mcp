"""CLI: python -m neuromap [serve|scan|map|selftest]"""
import argparse
import json
import sys


def main() -> int:
    ap = argparse.ArgumentParser(prog="neuromap")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("serve", help="run the MCP server on stdio")
    sc = sub.add_parser("scan", help="scan Azure now (read-only) and save a snapshot")
    sc.add_argument("--subscription", "-s", action="append", help="repeatable; default is all visible")
    sc.add_argument("--no-enrich", action="store_true", help="skip ARM child reads (verdicts become unknown)")
    sub.add_parser("map", help="write the HTML map for the latest snapshot")
    rb = sub.add_parser("rebuild", help="rebuild the graph from the saved raw scan (no Azure calls)")
    rb.add_argument("--snapshot", help="stamp; default is the latest")
    sub.add_parser("selftest", help="offline tests, no Azure needed")
    a = ap.parse_args()

    if a.cmd == "serve":
        from .server import main as serve
        serve()
        return 0
    if a.cmd == "selftest":
        from .selftest import run
        return run()
    from . import graph as G, store
    if a.cmd == "scan":
        from .collector import AzureCollector
        stamp, g = store.save(AzureCollector().collect(a.subscription, enrich=not a.no_enrich))
        print(json.dumps({"snapshot": stamp, **G.summary(g)}, indent=2))
        return 0
    if a.cmd == "rebuild":
        stamp, g = store.rebuild(a.snapshot)
        print(json.dumps({"snapshot": stamp, "rebuilt": True, **G.summary(g)}, indent=2))
        return 0
    if a.cmd == "map":
        from .server import export_map
        print(json.dumps(export_map(), indent=2))
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
