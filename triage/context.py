"""② 맥락 — 자산 정보(노출·중요도)와 도달 가능성. LLM 없음.

도달 가능성은 import·호출 패턴 수준의 휴리스틱이다. 규칙이 없으면 unknown 으로 남긴다.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from .collect import Finding
from .evidence import EvidenceStore

SOURCE_SUFFIXES = {".java", ".kt", ".py", ".js", ".ts", ".go"}


def load_assets(path: Path) -> dict:
    return yaml.safe_load(path.read_text())["services"]


def _source_text(root: Path) -> str:
    chunks = []
    for p in sorted(root.rglob("*")):
        if p.suffix in SOURCE_SUFFIXES and p.is_file():
            chunks.append(p.read_text(errors="ignore"))
    return "\n".join(chunks)


def reachability(package: str, source: str, rules: list[dict]) -> tuple[str, str]:
    rule = next((r for r in rules if r["package"] == package), None)
    if rule is None:
        return "unknown", "이 패키지에 대한 도달 규칙이 없음"
    hits = [s for s in rule["any_of"] if s in source]
    if not hits:
        return "not_reachable", f"소스에서 {', '.join(rule['any_of'])} 사용이 보이지 않음"
    needs = rule.get("requires_any")
    if needs and not any(s in source for s in needs):
        return "not_reachable", f"{hits[0]} 는 쓰지만 취약 조건({', '.join(needs)})이 보이지 않음"
    return "reachable", f"소스에서 {', '.join(hits)} 사용 확인"


def add_context(findings: list[Finding], store: EvidenceStore, assets: dict,
                rules_path: Path, project_root: Path) -> dict[str, dict]:
    rules = yaml.safe_load(rules_path.read_text())["rules"]
    out: dict[str, dict] = {}
    sources: dict[str, str] = {}
    for f in findings:
        a = assets[f.service]
        if f.service not in sources:
            sources[f.service] = _source_text(project_root / a["source_dir"])
        state, why = reachability(f.package, sources[f.service], rules)
        f.evidence.append(store.add("retrieved", "assets.yaml", f.key,
                                    f"{f.service} 는 노출 {a['exposure']}, 중요도 {a['criticality']}",
                                    {"owner": a.get("owner")}))
        f.evidence.append(store.add("derived", "reachability-rules", f.key,
                                    f"도달 가능성 {state}: {why}"))
        out[f.key] = {"exposure": a["exposure"], "criticality": a["criticality"],
                      "owner": a.get("owner"), "reachability": state}
    return out
