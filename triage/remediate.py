"""④ 조치 — 패키지 단위로 묶어 목표 버전을 정하고, 레지스트리에 실제로 있는 버전만 쓴다.

순서:
  1. 패키지의 모든 CVE 를 고치는 최소 버전(목표 버전)을 규칙으로 계산
  2. Maven Central 에 그 버전이 실제로 있는지 확인 — 없으면 "판단 불가", 패치도 만들지 않음
  3. 메이저 버전이 바뀌는지 표시
  4. pom.xml 버전 변경 diff(PR 초안) 생성
  5. LLM 이 조치안 문장을 쓴다 — 인용한 근거 ID 와 언급한 버전을 검증하고, 어기면 템플릿으로 대체
     (패키지끼리 독립이라 동시에 부른다. 근거 ID 는 자리를 먼저 잡아 순차 실행 때와 같다)
"""

from __future__ import annotations

import difflib
import json
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

import requests

from .evidence import EvidenceStore
from .llm import write_advice
from .score import Scored

MAVEN = "https://repo1.maven.org/maven2"


def vkey(v: str) -> tuple:
    nums = [int(x) for x in re.findall(r"\d+", v)]
    return tuple(nums) + (0,) * (6 - len(nums))


@dataclass
class Plan:
    package: str
    group: str | None
    service: str
    current: str
    target: str | None
    verified: bool
    major_bump: bool | None
    tier: str
    top_score: float
    vulns: list[str]               # 이 조치로 해소되는 CVE (추적 등급 포함)
    remaining: list[str]           # 목표 버전으로도 남는 CVE
    patch: str | None
    advice: dict
    advice_source: str            # llm | template
    evidence: list[str] = field(default_factory=list)
    fallback: dict | None = None  # LLM 출력을 템플릿으로 대체한 이유 (cli 가 rejections.jsonl 에 남김)


def target_version(items: list[Scored]) -> str | None:
    mins = []
    for s in items:
        fixes = s.finding.fixed_versions
        if not fixes:
            return None          # 고칠 버전이 없는 CVE 가 하나라도 있으면 버전 업만으로는 못 끝냄
        mins.append(min(fixes, key=vkey))
    return max(mins, key=vkey) if mins else None


def registry_versions(group: str, artifact: str, cache: Path, offline: bool) -> list[str] | None:
    path = cache / "registry.json"
    db = json.loads(path.read_text()) if path.exists() else {}
    key = f"maven:{group}:{artifact}"
    if key in db or offline:
        return db.get(key)
    url = f"{MAVEN}/{group.replace('.', '/')}/{artifact}/maven-metadata.xml"
    r = requests.get(url, timeout=20)
    if r.status_code == 404:
        db[key] = []
    else:
        r.raise_for_status()
        db[key] = re.findall(r"<version>([^<]+)</version>", r.text)
    path.write_text(json.dumps(db, indent=1))
    return db[key]


def pom_patch(pom: Path, group: str, artifact: str, current: str, target: str) -> str | None:
    text = pom.read_text()
    pattern = re.compile(
        rf"(<groupId>{re.escape(group)}</groupId>\s*<artifactId>{re.escape(artifact)}</artifactId>\s*<version>)"
        rf"{re.escape(current)}(</version>)")
    new, n = pattern.subn(rf"\g<1>{target}\g<2>", text)
    if n == 0:
        return None
    rel = f"{pom.parent.name}/{pom.name}"
    return "".join(difflib.unified_diff(text.splitlines(True), new.splitlines(True),
                                        fromfile=f"a/{rel}", tofile=f"b/{rel}"))


def plan_remediations(scored: list[Scored], store: EvidenceStore, assets: dict, root: Path,
                      cache: Path, offline: bool, tiers=("act", "attend")) -> list[Plan]:
    by_pkg: dict[tuple, list[Scored]] = {}
    for s in scored:
        f = s.finding
        by_pkg.setdefault((f.service, f.group, f.package, f.version), []).append(s)
    groups: dict[tuple, list[Scored]] = {}
    for s in scored:
        if s.tier in tiers:
            f = s.finding
            groups.setdefault((f.service, f.group, f.package, f.version), []).append(s)

    plans, jobs = [], []
    for (service, group, package, current), items in groups.items():
        items.sort(key=lambda s: -s.score)
        top = items[0]
        cites = [e for s in items for e in s.finding.evidence]
        target = target_version(items)
        versions = registry_versions(group, package, cache, offline) if (group and target) else None
        verified = bool(target and versions and target in versions)
        reg_claim = ("레지스트리 조회 안 함 (목표 버전 없음)" if not target else
                     f"Maven Central 에 {group}:{package}:{target} {'존재 확인' if verified else '확인 실패'}")
        reg_id = store.add("retrieved", "Maven Central", f"{package}@{current}", reg_claim,
                           {"target": target, "verified": verified})
        major = (vkey(target)[0] != vkey(current)[0]) if verified else None
        every = by_pkg[(service, group, package, current)]
        fixed_by = lambda s: bool(s.finding.fixed_versions) and vkey(target) >= vkey(min(s.finding.fixed_versions, key=vkey))
        resolved = [s.finding.vuln_id for s in every if verified and fixed_by(s)]
        remaining = [s.finding.vuln_id for s in every if s.finding.vuln_id not in resolved]
        vulns = resolved or [s.finding.vuln_id for s in items]
        patch = None
        if verified:
            patch = pom_patch(root / assets[service]["source_dir"] / "pom.xml", group, package, current, target)
        plan_id = store.add("derived", "remediate", f"{package}@{current}",
                            (f"목표 버전 {target} (메이저 변경 {'있음' if major else '없음'}), CVE {len(resolved)}건 해소"
                             + (f", {len(remaining)}건은 남음 ({', '.join(remaining)})" if remaining else "")
                             if verified else "확인된 수정 버전 없음 → 버전 업 조치안 판단 불가"),
                            {"resolved": resolved, "remaining": remaining}, cites=[reg_id] + cites)
        adv_id = store.reserve()   # 조치안 근거는 Claude 응답이 오면 채운다
        evidence_lines = {eid: store.get(eid).claim for eid in [plan_id, reg_id] + cites}
        plans.append(Plan(package, group, service, current, target if verified else None, verified, major,
                          top.tier, top.score, vulns, remaining, patch, {}, "", [plan_id, reg_id, adv_id]))
        jobs.append(dict(package=package, group=group, current=current, target=target if verified else None,
                         major_bump=major, vulns=vulns, evidence=evidence_lines, registry_versions=versions or ()))

    # Claude 호출은 패키지마다 10초 남짓이라 차례로 부르면 패키지 수만큼 길어진다
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda job: write_advice(**job), jobs))
    for plan, (advice, src, fallback) in zip(plans, results):
        plan.advice, plan.advice_source, plan.fallback = advice, src, fallback
        store.fill(plan.evidence[2], "generated", f"advice:{src}", f"{plan.package}@{plan.current}",
                   advice["summary"], {"advice": advice}, cites=advice["cited_evidence"])
    plans.sort(key=lambda p: -p.top_score)
    return plans
