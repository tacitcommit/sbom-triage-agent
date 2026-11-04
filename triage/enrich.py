"""외부 위협 데이터 — FIRST EPSS, CISA KEV. 결과는 data/cache 에 저장해 오프라인 재실행에 쓴다."""

from __future__ import annotations

import json
from pathlib import Path

import requests

from .collect import Finding
from .evidence import EvidenceStore

EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
TIMEOUT = 20


def fetch_epss(cves: list[str], cache: Path, offline: bool) -> dict[str, dict]:
    path = cache / "epss.json"
    cached = json.loads(path.read_text()) if path.exists() else {}
    if offline:
        return cached
    todo = [c for c in cves if c not in cached]
    for i in range(0, len(todo), 50):
        batch = todo[i:i + 50]
        r = requests.get(EPSS_URL, params={"cve": ",".join(batch)}, timeout=TIMEOUT)
        r.raise_for_status()
        for row in r.json().get("data", []):
            cached[row["cve"]] = {"epss": float(row["epss"]), "percentile": float(row["percentile"]),
                                  "date": row.get("date")}
    path.write_text(json.dumps(cached, indent=1))
    return cached


def fetch_kev(cache: Path, offline: bool) -> dict[str, dict]:
    path = cache / "kev.json"
    if offline or path.exists():
        if not path.exists():
            return {}
        doc = json.loads(path.read_text())
    else:
        r = requests.get(KEV_URL, timeout=TIMEOUT)
        r.raise_for_status()
        doc = r.json()
        path.write_text(json.dumps(doc))
    return {v["cveID"]: {"dateAdded": v.get("dateAdded"), "name": v.get("vulnerabilityName")}
            for v in doc.get("vulnerabilities", [])}


def enrich(findings: list[Finding], store: EvidenceStore, cache: Path, offline: bool) -> dict[str, dict]:
    cache.mkdir(parents=True, exist_ok=True)
    cves = sorted({f.vuln_id for f in findings if f.vuln_id.startswith("CVE-")})
    epss = fetch_epss(cves, cache, offline)
    kev = fetch_kev(cache, offline)
    out: dict[str, dict] = {}
    for f in findings:
        e = epss.get(f.vuln_id)
        k = kev.get(f.vuln_id)
        info = {"epss": e["epss"] if e else None, "epss_percentile": e["percentile"] if e else None,
                "kev": bool(k), "kev_date": k["dateAdded"] if k else None}
        if e:
            f.evidence.append(store.add("retrieved", "FIRST EPSS", f.key,
                                        f"{f.vuln_id} 의 30일 내 악용 확률 {e['epss']:.3f} (백분위 {e['percentile']:.2f})",
                                        {"date": e.get("date")}))
        else:
            f.evidence.append(store.add("retrieved", "FIRST EPSS", f.key, f"{f.vuln_id} 의 EPSS 값을 찾지 못함"))
        f.evidence.append(store.add("retrieved", "CISA KEV", f.key,
                                    f"{f.vuln_id} 는 KEV 에 {'등재됨 (' + str(k['dateAdded']) + ')' if k else '없음'}"))
        out[f.key] = info
    return out
