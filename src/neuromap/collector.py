"""Read-only Azure collector.

Calls made, all read-only:
  * GET  /subscriptions
  * POST /providers/Microsoft.ResourceGraph/resources      (KQL: resources, containers, role assignments)
  * GET  /subscriptions/{id}/providers/Microsoft.Authorization/roleDefinitions
  * GET  <resource>/<child>?api-version=<pinned>             (ENRICH table in queries.py)

Needs Reader. Anything that cannot be read is recorded with its HTTP status so
the graph reports it as unknown instead of guessing.
"""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any

import httpx

from .queries import CONTAINERS, ENRICH, INVENTORY, ROLE_ASSIGNMENTS, ROLE_DEFINITIONS_API

ARM = "https://management.azure.com"
SCOPE = "https://management.azure.com/.default"
ARG_API = "2022-10-01"
SUBS_API = "2022-12-01"
SUB_BATCH = 1000
PAGE_SIZE = 1000


class CollectorError(RuntimeError):
    def __init__(self, msg: str, status: int | None = None):
        super().__init__(msg)
        self.status = status


def _default_credential():
    from azure.identity import DefaultAzureCredential

    return DefaultAzureCredential(exclude_interactive_browser_credential=True)


class AzureCollector:
    def __init__(self, credential: Any | None = None, timeout: float = 120.0, workers: int = 8):
        self._cred = credential or _default_credential()
        self._http = httpx.Client(timeout=timeout)
        self._workers = workers

    # ---- plumbing -------------------------------------------------------
    def _headers(self) -> dict[str, str]:
        token = self._cred.get_token(SCOPE).token
        return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    def _send(self, method: str, url: str, **kw) -> dict:
        for attempt in range(6):
            r = self._http.request(method, url, headers=self._headers(), **kw)
            if r.status_code == 429 or r.status_code >= 500:
                time.sleep(min(float(r.headers.get("Retry-After", 2 ** attempt)), 60))
                continue
            if r.status_code >= 400:
                raise CollectorError(f"{method} {url.split('?')[0]} -> {r.status_code}: {r.text[:400]}",
                                     r.status_code)
            return r.json()
        raise CollectorError(f"{method} {url} kept throttling after retries", 429)

    def _get_all(self, url: str) -> list[dict]:
        items: list[dict] = []
        while url:
            body = self._send("GET", url)
            items.extend(body.get("value", []))
            url = body.get("nextLink")
        return items

    # ---- Resource Graph ---------------------------------------------------
    def query(self, kql: str, subscription_ids: list[str]) -> list[dict]:
        url = f"{ARM}/providers/Microsoft.ResourceGraph/resources?api-version={ARG_API}"
        rows: list[dict] = []
        for i in range(0, len(subscription_ids), SUB_BATCH):
            batch = subscription_ids[i : i + SUB_BATCH]
            skip, top = None, PAGE_SIZE
            while True:
                options: dict[str, Any] = {"$top": top, "resultFormat": "objectArray"}
                if skip:
                    options["$skipToken"] = skip
                try:
                    body = self._send("POST", url, json={"subscriptions": batch, "query": kql, "options": options})
                except CollectorError as e:
                    # Large property bags can exceed the response limit: shrink the page and retry.
                    if "toolarge" in str(e).lower().replace(" ", "") and top > 25:
                        top //= 2
                        continue
                    raise
                rows.extend(body.get("data", []))
                skip = body.get("$skipToken")
                if not skip:
                    break
        return rows

    # ---- public -----------------------------------------------------------
    def list_subscriptions(self) -> list[dict]:
        return [{"id": s["subscriptionId"], "name": s.get("displayName"), "state": s.get("state"),
                 "tenantId": s.get("tenantId")}
                for s in self._get_all(f"{ARM}/subscriptions?api-version={SUBS_API}")]

    def _role_definitions(self, subs: list[str], errors: list) -> dict[str, dict]:
        defs: dict[str, dict] = {}
        for sid in subs:
            try:
                for d in self._get_all(f"{ARM}/subscriptions/{sid}/providers/Microsoft.Authorization/"
                                       f"roleDefinitions?api-version={ROLE_DEFINITIONS_API}"):
                    p = d.get("properties", {})
                    perms = p.get("permissions") or []
                    defs[d["name"].lower()] = {
                        "name": p.get("roleName"), "type": p.get("type"),
                        "actions": sorted({a for x in perms for a in x.get("actions") or []}),
                        "not_actions": sorted({a for x in perms for a in x.get("notActions") or []}),
                        "data_actions": sorted({a for x in perms for a in x.get("dataActions") or []}),
                        "not_data_actions": sorted({a for x in perms for a in x.get("notDataActions") or []})}
            except CollectorError as e:
                errors.append({"step": "role_definitions", "subscription": sid, "status": e.status, "error": str(e)})
        return defs

    def _assignments_above_subscription(self, subs: list[str], errors: list) -> tuple[list[dict], bool]:
        """Resource Graph queried by subscription does not return assignments made at management
        group or root scope. $filter=atScope() at the subscription returns those (Reader is enough)."""
        out: dict[str, dict] = {}
        ok = True
        for sid in subs:
            try:
                for a in self._get_all(f"{ARM}/subscriptions/{sid}/providers/Microsoft.Authorization/"
                                       f"roleAssignments?api-version={ROLE_DEFINITIONS_API}&$filter=atScope()"):
                    scope = ((a.get("properties") or {}).get("scope") or "").lower()
                    if not scope.startswith("/subscriptions/"):
                        out[a["id"].lower()] = {"id": a["id"], "properties": a.get("properties") or {}}
            except CollectorError as e:
                ok = False
                errors.append({"step": "role_assignments_above_subscription", "subscription": sid,
                               "status": e.status, "error": str(e)})
        return list(out.values()), ok

    def _enrich_one(self, rid: str, key: str, suffix: str, api: str, is_list: bool) -> tuple[str, str, dict]:
        url = f"{ARM}{rid}{suffix}?api-version={api}"
        try:
            data = self._get_all(url) if is_list else self._send("GET", url)
            return rid.lower(), key, {"api": api, "data": data}
        except CollectorError as e:
            return rid.lower(), key, {"api": api, "error": str(e), "status": e.status}

    def enrich(self, resources: list[dict]) -> dict[str, dict]:
        jobs = [(r["id"], *spec) for r in resources for spec in ENRICH.get(r["type"].lower(), [])]
        out: dict[str, dict] = {}
        with ThreadPoolExecutor(max_workers=self._workers) as pool:
            for rid, key, res in pool.map(lambda j: self._enrich_one(*j), jobs):
                out.setdefault(rid, {})[key] = res
        return out

    def collect(self, subscription_ids: list[str] | None = None, enrich: bool = True) -> dict:
        errors: list[dict] = []
        enabled = [s for s in self.list_subscriptions() if s.get("state") == "Enabled"]
        if subscription_ids:
            wanted = {s.lower() for s in subscription_ids}
            chosen = [s for s in enabled if s["id"].lower() in wanted]
            missing = sorted(wanted - {s["id"].lower() for s in chosen})
        else:
            chosen, missing = enabled, []
        if not chosen:
            raise CollectorError("No enabled subscriptions visible to this identity"
                                 + (f" (requested but not visible: {missing})" if missing else ""))
        ids = [s["id"] for s in chosen]
        resources = self.query(INVENTORY, ids)
        containers = self.query(CONTAINERS, ids)
        try:
            assignments, rbac_status = self.query(ROLE_ASSIGNMENTS, ids), "ok"
        except CollectorError as e:
            assignments, rbac_status = [], f"unreadable: {e}"
            errors.append({"step": "role_assignments", "status": e.status, "error": str(e)})
        above, above_ok = self._assignments_above_subscription(ids, errors)
        known = {a["id"].lower() for a in assignments}
        assignments += [a for a in above if a["id"].lower() not in known]
        role_defs = self._role_definitions(ids, errors) if assignments else {}
        arm = self.enrich(resources) if enrich else {}
        return {
            "schema": 2,
            "collected_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "subscriptions": chosen,
            "not_visible": missing,
            "resources": resources,
            "containers": containers,
            "role_assignments": assignments,
            "role_definitions": role_defs,
            "rbac_status": rbac_status,
            "rbac_coverage": {"subscription_and_below": rbac_status == "ok", "above_subscription": above_ok},
            "enriched": enrich,
            "arm": arm,
            "errors": errors,
        }
