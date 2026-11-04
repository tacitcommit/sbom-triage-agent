"""실행: python -m triage.cli run --service order-api

  기본    : syft·grype 실행, EPSS·KEV·Maven Central 조회 (결과는 data/cache 에 저장)
  --offline: syft·grype 대신 --grype 로 준 JSON 을 쓰고, 외부 조회는 data/cache 만 사용
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path

from . import collect, context, enrich, remediate, report, score
from .evidence import EvidenceStore

ROOT = Path(__file__).resolve().parent.parent


def run(args: argparse.Namespace) -> Path:
    root = Path(args.root).resolve()
    out = Path(args.out).resolve()
    cache = Path(args.cache).resolve()
    out.mkdir(parents=True, exist_ok=True)
    assets = context.load_assets(root / "config" / "assets.yaml")
    svc = assets[args.service]
    store = EvidenceStore()

    # ① 수집
    if args.offline:
        grype_json = Path(args.grype).resolve()
    else:
        sbom = collect.run_syft(root / svc["source_dir"], out)
        store.add("observed", "syft", args.service, f"SBOM 생성: {sbom.name}")
        grype_json = collect.run_grype(sbom, out)
    findings = collect.parse_grype(grype_json, args.service, store)
    print(f"① 수집: 취약점 매칭 {len(findings)}건")

    # 외부 위협 데이터 + ② 맥락
    threat = enrich.enrich(findings, store, cache, args.offline)
    ctx = context.add_context(findings, store, assets, root / "config" / "reachability_rules.yaml", root)
    print(f"② 맥락: 노출 {svc['exposure']} · 중요도 {svc['criticality']} · 도달 판정 완료")

    # ③ 우선순위
    cfg = score.load_config(root / "config" / "scoring.yaml")
    scored = score.prioritize(findings, threat, ctx, store, cfg)
    act = sum(1 for s in scored if s.tier == "act")
    print(f"③ 우선순위: 이번 주 조치 {act}건 / 전체 {len(scored)}건")

    # ④ 조치
    plans = remediate.plan_remediations(scored, store, assets, root, cache, args.offline)
    print(f"④ 조치: 패키지 {len(plans)}개 조치안, PR 초안 {sum(1 for p in plans if p.patch)}개")

    meta = {"service": args.service, "run_at": dt.datetime.now().strftime("%Y-%m-%d %H:%M"),
            "mode": "offline" if args.offline else "online"}
    path = report.write(out, scored, plans, store, meta)
    print(f"보고서: {path}")
    log_fallbacks(out / "rejections.jsonl", plans, meta)
    return path


def log_fallbacks(path: Path, plans: list[remediate.Plan], meta: dict) -> None:
    """LLM 조치안이 템플릿으로 대체될 때마다 이유를 한 줄씩 덧붙인다 (지난 실행 기록도 남긴다)."""
    fell = [p for p in plans if p.fallback]
    if not fell:
        return
    with path.open("a", encoding="utf-8") as f:
        for p in fell:
            f.write(json.dumps({"run_at": meta["run_at"], "service": p.service, "package": p.package,
                                "current": p.current, "target": p.target, **p.fallback},
                               ensure_ascii=False) + "\n")
    print(f"템플릿 대체 {len(fell)}건 ({', '.join(p.package for p in fell)}) → {path}")


def main() -> None:
    p = argparse.ArgumentParser(prog="triage")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--service", default="order-api")
    r.add_argument("--root", default=str(ROOT))
    r.add_argument("--out", default=str(ROOT / "out"))
    r.add_argument("--cache", default=str(ROOT / "data" / "cache"))
    r.add_argument("--offline", action="store_true")
    r.add_argument("--grype", help="--offline 일 때 쓸 grype JSON")
    args = p.parse_args()
    if args.cmd == "run":
        if args.offline and not args.grype:
            p.error("--offline 에는 --grype <json> 이 필요합니다")
        run(args)


if __name__ == "__main__":
    main()
