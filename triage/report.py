"""보고서 — 담당자가 받는 한 장. 모든 줄이 근거 ID 를 단다."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from .evidence import EvidenceStore
from .remediate import Plan
from .score import Scored

TIER_KO = {"act": "이번 주 조치", "attend": "다음 정기 패치", "track": "추적"}


def write(out: Path, scored: list[Scored], plans: list[Plan], store: EvidenceStore, meta: dict) -> Path:
    out.mkdir(parents=True, exist_ok=True)
    store.dump(out / "evidence.jsonl")
    for p in plans:
        if p.patch:
            (out / f"pr-{p.package}-{p.target}.patch").write_text(p.patch)

    counts = {t: sum(1 for s in scored if s.tier == t) for t in TIER_KO}
    lines = [
        f"# 공급망 위험 트리아지 — {meta['service']}",
        "",
        f"실행 {meta['run_at']} · 모드 {meta['mode']} · 근거 {len(store)}건",
        "",
        f"스캐너가 찾은 취약점 **{len(scored)}건** 중 이번 주 조치 **{counts['act']}건**, "
        f"다음 정기 패치 {counts['attend']}건, 추적 {counts['track']}건.",
        "",
        "## 조치 목록 (패키지 단위)",
        "",
        "| 등급 | 패키지 | 현재 → 목표 | 메이저 변경 | 해소 CVE | 남는 CVE | 작성 | 근거 |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for p in plans:
        tgt = p.target or "판단 불가"
        major = "-" if p.major_bump is None else ("있음" if p.major_bump else "없음")
        lines.append(f"| {TIER_KO[p.tier]} | {p.package} | {p.current} → {tgt} | {major} | "
                     f"{', '.join(p.vulns)} | {', '.join(p.remaining) or '-'} | {p.advice_source} | {', '.join(p.evidence)} |")
    lines += ["", "## 전체 취약점 순위", "",
              "| 순위 | 점수 | 등급 | CVE | 패키지 | CVSS | EPSS | KEV | 도달 | 근거 |",
              "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
    for i, s in enumerate(scored, 1):
        f = s.finding
        reach = next((store.get(e).claim.split(":")[0].replace("도달 가능성 ", "")
                      for e in f.evidence if store.get(e).source == "reachability-rules"), "-")
        epss_txt = next((store.get(e).claim.split("확률 ")[1].split(" ")[0]
                         for e in f.evidence if store.get(e).source == "FIRST EPSS" and "확률" in store.get(e).claim), "-")
        kev = any("등재됨" in store.get(e).claim for e in f.evidence if store.get(e).source == "CISA KEV")
        lines.append(f"| {i} | {s.score} | {TIER_KO[s.tier]} | {f.vuln_id} | {f.package} {f.version} | "
                     f"{f.cvss if f.cvss is not None else '-'} | {epss_txt} | {'O' if kev else '-'} | {reach} | {s.evidence_id} |")
    lines += ["", "## 조치안 상세", ""]
    for p in plans:
        a = p.advice
        lines += [f"### {p.package} {p.current} → {p.target or '판단 불가'}", "",
                  a["summary"], ""]
        lines += [f"{n}. {step}" for n, step in enumerate(a["steps"], 1)]
        lines += ["", f"- 호환성: {a['breaking_change_risk']}", f"- 임시 완화: {a['interim_mitigation']}",
                  f"- 인용 근거: {', '.join(a['cited_evidence'])} · 작성: {p.advice_source}"]
        if p.patch:
            lines += ["", f"PR 초안: `pr-{p.package}-{p.target}.patch`", "", "```diff", p.patch.rstrip(), "```"]
        lines.append("")
    lines += ["---", "점수는 config/scoring.yaml 의 규칙으로만 계산했다. LLM 은 조치안 문장만 썼고, "
              "인용 근거와 버전이 검증을 통과하지 못하면 템플릿으로 대체했다. 도달 가능성은 import·호출 패턴 휴리스틱이다."]
    path = out / "report.md"
    path.write_text("\n".join(lines), encoding="utf-8")
    (out / "report.json").write_text(json.dumps({
        "meta": meta,
        "ranking": [{"rank": i, "score": s.score, "tier": s.tier, "vuln": s.finding.vuln_id,
                     "package": s.finding.package, "version": s.finding.version, "parts": s.parts,
                     "evidence": s.evidence_id} for i, s in enumerate(scored, 1)],
        "plans": [{k: v for k, v in asdict(p).items() if k not in ("patch", "fallback")} for p in plans],
    }, ensure_ascii=False, indent=1))
    return path
