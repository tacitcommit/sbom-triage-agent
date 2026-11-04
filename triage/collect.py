"""① 수집 — Syft 로 SBOM, Grype 로 취약점 매칭. LLM 없음."""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .evidence import EvidenceStore


@dataclass
class Finding:
    key: str                  # "<cve>|<package>@<version>"
    vuln_id: str              # CVE 우선, 없으면 GHSA 등
    aliases: list[str]
    package: str              # Maven artifactId 등
    group: str | None
    version: str
    ecosystem: str
    purl: str
    severity: str
    cvss: float | None
    fixed_versions: list[str]
    service: str
    evidence: list[str] = field(default_factory=list)


def run_syft(source_dir: Path, out: Path) -> Path:
    if not shutil.which("syft"):
        raise RuntimeError("syft 가 없습니다. `brew install syft` 후 다시 실행하세요 (오프라인 데모는 --offline).")
    sbom = out / "sbom.cdx.json"
    # -q: 진행 표시·경고를 숨겨 실행 로그가 ①~④ 단계만 보이게 한다 (실패하면 check=True 가 멈춘다)
    subprocess.run(["syft", f"dir:{source_dir}", "-q", "-o", f"cyclonedx-json={sbom}"], check=True)
    return sbom


def run_grype(sbom: Path, out: Path) -> Path:
    if not shutil.which("grype"):
        raise RuntimeError("grype 가 없습니다. `brew install grype` 후 다시 실행하세요 (오프라인 데모는 --offline).")
    result = out / "grype.json"
    with result.open("w") as f:
        subprocess.run(["grype", f"sbom:{sbom}", "-q", "-o", "json"], check=True, stdout=f)
    return result


def _max_cvss(entries: list[dict]) -> float | None:
    scores = []
    for c in entries or []:
        s = (c.get("metrics") or {}).get("baseScore")
        if isinstance(s, (int, float)):
            scores.append(float(s))
    return max(scores) if scores else None


def _group_from_purl(purl: str) -> str | None:
    # pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1
    if purl.startswith("pkg:maven/"):
        rest = purl[len("pkg:maven/"):].split("@")[0]
        parts = rest.split("/")
        if len(parts) == 2:
            return parts[0]
    return None


def parse_grype(path: Path, service: str, store: EvidenceStore) -> list[Finding]:
    doc = json.loads(path.read_text())
    findings: dict[str, Finding] = {}
    for m in doc.get("matches", []):
        v = m.get("vulnerability", {})
        a = m.get("artifact", {})
        related = m.get("relatedVulnerabilities", []) or []
        ids = [v.get("id", "")] + [r.get("id", "") for r in related]
        cve = next((i for i in ids if i.startswith("CVE-")), None)
        vuln_id = cve or v.get("id", "UNKNOWN")
        aliases = sorted({i for i in ids if i and i != vuln_id})
        cvss = _max_cvss(v.get("cvss", []) + [c for r in related for c in (r.get("cvss") or [])])
        purl = a.get("purl", "")
        key = f"{vuln_id}|{a.get('name')}@{a.get('version')}"
        if key in findings:  # GHSA 와 CVE 가 같은 취약점으로 두 번 매칭되면 하나로
            f = findings[key]
            f.aliases = sorted(set(f.aliases) | set(aliases))
            f.cvss = max(filter(None, [f.cvss, cvss]), default=None)
            continue
        fix = v.get("fix", {}) or {}
        f = Finding(
            key=key, vuln_id=vuln_id, aliases=aliases,
            package=a.get("name", ""), group=_group_from_purl(purl), version=a.get("version", ""),
            ecosystem=a.get("type", ""), purl=purl, severity=v.get("severity", "Unknown"),
            cvss=cvss, fixed_versions=list(fix.get("versions", []) or []), service=service,
        )
        f.evidence.append(store.add(
            "observed", "grype", key,
            f"{f.package} {f.version} 이(가) {vuln_id} 에 해당 (심각도 {f.severity}, CVSS {cvss if cvss is not None else '없음'})",
            {"purl": purl, "fixed_versions": f.fixed_versions, "aliases": aliases},
        ))
        findings[key] = f
    return list(findings.values())
