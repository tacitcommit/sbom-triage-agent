"""③ 우선순위 — 규칙으로만 계산한다. 같은 입력이면 항상 같은 점수와 순위."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from .collect import Finding
from .evidence import EvidenceStore


@dataclass
class Scored:
    finding: Finding
    score: float
    tier: str              # act | attend | track
    parts: dict[str, float]
    evidence_id: str


def load_config(path: Path) -> dict:
    return yaml.safe_load(path.read_text())


def compute(cvss: float | None, epss: float | None, kev: bool, exposure: str,
            reach: str, criticality: str, cfg: dict) -> tuple[float, dict[str, float]]:
    w = cfg["weights"]
    parts = {
        "cvss": round(cvss / 10 * w["cvss_max"], 2) if cvss is not None else float(w["cvss_unknown"]),
        "epss": round((epss or 0.0) * w["epss_max"], 2),
        "kev": float(w["kev"]) if kev else 0.0,
        "exposure": float(w["exposure"].get(exposure, 0)),
        "reachability": float(w["reachability"].get(reach, 0)),
    }
    mult = cfg["criticality_multiplier"].get(criticality, 1.0)
    score = round(min(100.0, sum(parts.values()) * mult), 1)
    parts["multiplier"] = mult
    return score, parts


def tier_of(score: float, cfg: dict) -> str:
    t = cfg["tiers"]
    return "act" if score >= t["act"] else "attend" if score >= t["attend"] else "track"


def prioritize(findings: list[Finding], threat: dict[str, dict], ctx: dict[str, dict],
               store: EvidenceStore, cfg: dict) -> list[Scored]:
    out = []
    for f in findings:
        th, cx = threat[f.key], ctx[f.key]
        score, parts = compute(f.cvss, th["epss"], th["kev"], cx["exposure"],
                               cx["reachability"], cx["criticality"], cfg)
        tier = tier_of(score, cfg)
        eid = store.add("derived", "scoring.yaml", f.key,
                        f"위험 점수 {score} → {tier} "
                        f"(CVSS {parts['cvss']} + EPSS {parts['epss']} + KEV {parts['kev']} "
                        f"+ 노출 {parts['exposure']} + 도달 {parts['reachability']}) × {parts['multiplier']}",
                        {"parts": parts}, cites=list(f.evidence))
        f.evidence.append(eid)
        out.append(Scored(f, score, tier, parts, eid))
    # 동점이면 CVE ID 로 정렬해 순서까지 결정적으로
    out.sort(key=lambda s: (-s.score, s.finding.vuln_id, s.finding.package))
    return out
