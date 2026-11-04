"""오프라인 픽스처(합성 데이터)로 신뢰성 장치를 검증한다."""

import argparse
import copy
import json
import shutil
import threading
from pathlib import Path

import pytest

from triage import cli, collect, context, enrich, llm, remediate, score
from triage.evidence import EvidenceStore
from triage.llm import _valid, template

ROOT = Path(__file__).resolve().parent.parent
FIX = ROOT / "tests" / "fixtures"
CLAUDE = json.loads((FIX / "claude_advice.json").read_text())
RECORDED = CLAUDE["advice"]
JACKSON_LINE = CLAUDE["variants"]["jackson-databind"]     # "2.9.x" 버전 라인 표기를 쓴 실제 응답


@pytest.fixture(autouse=True)
def no_api_key(monkeypatch):
    # 셸에 실제 키가 있어도 테스트는 API 를 부르지 않는다
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)


def replay(monkeypatch, recorded):
    """API 대신 기록해 둔 Claude 출력을 돌려준다. 검증 게이트는 실제 경로 그대로 탄다."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "replay")
    monkeypatch.setattr(llm, "_ask_claude", lambda payload: recorded[payload["package"].split(":")[-1]])


def build(cache):
    store = EvidenceStore()
    assets = context.load_assets(ROOT / "config" / "assets.yaml")
    findings = collect.parse_grype(FIX / "grype_sample.json", "order-api", store)
    threat = enrich.enrich(findings, store, cache, offline=True)
    ctx = context.add_context(findings, store, assets, ROOT / "config" / "reachability_rules.yaml", ROOT)
    cfg = score.load_config(ROOT / "config" / "scoring.yaml")
    return score.prioritize(findings, threat, ctx, store, cfg)


@pytest.fixture
def pipeline(tmp_path):
    cache = tmp_path / "cache"
    shutil.copytree(FIX / "cache", cache)
    store = EvidenceStore()
    assets = context.load_assets(ROOT / "config" / "assets.yaml")
    findings = collect.parse_grype(FIX / "grype_sample.json", "order-api", store)
    threat = enrich.enrich(findings, store, cache, offline=True)
    ctx = context.add_context(findings, store, assets, ROOT / "config" / "reachability_rules.yaml", ROOT)
    cfg = score.load_config(ROOT / "config" / "scoring.yaml")
    scored = score.prioritize(findings, threat, ctx, store, cfg)
    return store, assets, findings, threat, ctx, cfg, scored, cache


def test_ghsa_alias_merged_into_cve(pipeline):
    _, _, findings, *_ = pipeline
    log4shell = [f for f in findings if f.vuln_id == "CVE-2021-44228"]
    assert len(log4shell) == 1
    assert "GHSA-jfh8-c2jp-5v3q" in log4shell[0].aliases


def test_scoring_is_deterministic(pipeline):
    *_, scored, cache = pipeline
    for _ in range(3):
        again = build(cache)
        assert [(s.finding.key, s.score, s.tier) for s in scored] == \
               [(s.finding.key, s.score, s.tier) for s in again]


def test_reachability_from_sample_source(pipeline):
    *_, ctx, _cfg, _scored, _cache = pipeline
    by_pkg = {k.split("|")[1].split("@")[0]: v["reachability"] for k, v in ctx.items()}
    assert by_pkg["log4j-core"] == "reachable"
    assert by_pkg["snakeyaml"] == "reachable"
    assert by_pkg["jackson-databind"] == "not_reachable"   # ObjectMapper 는 쓰지만 default typing 없음
    assert by_pkg["commons-text"] == "not_reachable"       # 선언만, 사용 안 함


def test_log4shell_ranks_first_and_unreachable_not_penalised(pipeline):
    *_, cfg, scored, _ = pipeline
    assert scored[0].finding.vuln_id == "CVE-2021-44228"
    assert scored[0].tier == "act"
    text = next(s for s in scored if s.finding.vuln_id == "CVE-2022-42889")
    assert text.parts["reachability"] == 0.0               # 감점 없음, 가산 없음


def test_every_derived_and_generated_evidence_cites_existing_ids(pipeline):
    store, assets, *_rest, scored, cache = pipeline
    remediate.plan_remediations(scored, store, assets, ROOT, cache, offline=True)
    for e in store._items.values():
        for c in e.cites:
            assert store.has(c)
        if e.kind == "generated":
            assert e.cites


def test_target_version_covers_all_cves(pipeline):
    store, assets, *_rest, scored, cache = pipeline
    plans = remediate.plan_remediations(scored, store, assets, ROOT, cache, offline=True)
    log4j = next(p for p in plans if p.package == "log4j-core")
    assert log4j.target == "2.17.1" and log4j.verified and log4j.major_bump is False
    assert "+      <version>2.17.1</version>" in log4j.patch


def test_unverified_version_is_never_recommended(pipeline, tmp_path):
    store, assets, *_rest, scored, cache = pipeline
    # 레지스트리에서 snakeyaml 2.0 을 지운다 → 조치안은 "판단 불가", 패치 없음
    import json
    reg = json.loads((cache / "registry.json").read_text())
    reg["maven:org.yaml:snakeyaml"] = ["1.30", "1.33"]
    (cache / "registry.json").write_text(json.dumps(reg))
    plans = remediate.plan_remediations(scored, store, assets, ROOT, cache, offline=True)
    sy = next((p for p in plans if p.package == "snakeyaml"), None)
    if sy is not None:
        assert sy.target is None and sy.patch is None
        assert "판단 불가" in sy.advice["summary"]


def test_llm_output_with_invented_version_is_rejected():
    ev = {"E-0001": "x", "E-0002": "y"}
    good = template("log4j-core", "2.14.1", "2.17.1", False, ["CVE-2021-44228"], ev)
    assert _valid(good, ev, {"2.14.1", "2.17.1"})
    bad = {**good, "summary": "2.18.0 으로 올리세요 (CVE-2021-44228)"}
    assert not _valid(bad, ev, {"2.14.1", "2.17.1"})
    particle = {**good, "summary": "2.18.0으로 올리세요"}            # 조사가 붙어도 끝까지 읽는다
    assert not _valid(particle, ev, {"2.14.1", "2.17.1"})
    period = {**good, "summary": "목표 버전은 2.18.0."}              # 문장 끝 마침표도
    assert not _valid(period, ev, {"2.14.1", "2.17.1"})
    fake_cite = {**good, "cited_evidence": ["E-9999"]}
    assert not _valid(fake_cite, ev, {"2.14.1", "2.17.1"})


def test_registry_version_rejected_even_if_cited():
    ev = {"E-0001": "log4j-core 2.14.1 이(가) CVE-2021-45046 에 해당, 2.16.0 에서 수정"}
    advice = {**template("log4j-core", "2.14.1", "2.17.1", False, ["CVE-2021-45046"], ev),
              "summary": "2.16.0 에서 수정된 CVE-2021-45046 도 2.17.1 로 해소된다."}
    allowed = {"2.14.1", "2.17.1"}
    assert _valid(advice, ev, allowed)                                          # 인용한 근거에 있는 숫자
    assert not _valid(advice, ev, allowed, ["2.14.1", "2.16.0", "2.17.1"])      # 하지만 레지스트리의 다른 버전


def test_version_line_allowed_only_for_current_or_target_line():
    ev = {"E-0001": "x"}
    base = template("jackson-databind", "2.9.10.1", "2.9.10.3", False, ["CVE-2020-8840"], ev)
    allowed = {"2.9.10.1", "2.9.10.3"}
    registry = ["2.9.10.1", "2.9.10.3", "2.12.6.1", "2.13.2.1"]
    risk = lambda text: {**base, "breaking_change_risk": text}
    assert _valid(risk("낮음. 2.9.x 내 패치 업그레이드"), ev, allowed, registry)
    assert _valid(risk("2.x 안에서의 변경"), ev, allowed, registry)
    assert not _valid(risk("낮음. 2.10.x 내 패치 업그레이드"), ev, allowed, registry)   # 다른 라인
    assert not _valid(risk("3.x 로 올리면 해소"), ev, allowed, registry)
    assert not _valid(risk("낮음. 2.9 내 패치 업그레이드"), ev, allowed, registry)       # x 가 없으면 그냥 숫자
    assert not _valid(risk("2.9.10 이면 충분"), ev, allowed, registry)                   # 2.9.10 은 다른 버전
    assert llm._problems(risk("2.10.x 내 변경"), ev, allowed, registry) == [
        {"field": "breaking_change_risk", "token": "2.10.x", "why": "현재·목표 버전이 속하지 않는 버전 라인"}]


def test_recorded_claude_advice_passes_gate(pipeline, monkeypatch):
    store, assets, *_rest, scored, cache = pipeline
    replay(monkeypatch, RECORDED)
    plans = remediate.plan_remediations(scored, store, assets, ROOT, cache, offline=True)
    assert {p.package: p.advice_source for p in plans} == {pkg: "llm" for pkg in RECORDED}


def test_recorded_claude_advice_with_invented_version_is_rejected(pipeline, monkeypatch):
    store, assets, *_rest, scored, cache = pipeline
    tampered = copy.deepcopy(RECORDED)
    tampered["log4j-core"]["steps"].append("여유가 되면 2.18.0으로 한 번 더 올립니다.")
    replay(monkeypatch, tampered)
    plans = remediate.plan_remediations(scored, store, assets, ROOT, cache, offline=True)
    log4j = next(p for p in plans if p.package == "log4j-core")
    assert log4j.advice_source == "template" and log4j.advice["llm_rejected"]
    assert log4j.fallback["problems"] == [{"field": "steps[4]", "token": "2.18.0",
                                           "why": "현재·목표 버전도 아니고 인용한 근거에도 없는 숫자"}]
    assert all(p.advice_source == "llm" for p in plans if p.package != "log4j-core")


def test_claude_calls_run_concurrently_with_same_evidence_ids(pipeline, monkeypatch):
    store, assets, *_rest, scored, cache = pipeline
    barrier = threading.Barrier(len(RECORDED), timeout=5)   # 4개가 동시에 들어와야 풀린다 (차례로 부르면 시간 초과 → 템플릿)

    def together(payload):
        barrier.wait()
        return RECORDED[payload["package"].split(":")[-1]]

    monkeypatch.setenv("ANTHROPIC_API_KEY", "replay")
    monkeypatch.setattr(llm, "_ask_claude", together)
    plans = remediate.plan_remediations(scored, store, assets, ROOT, cache, offline=True)
    assert [p.advice_source for p in plans] == ["llm"] * 4
    # 근거 ID 는 순차 실행 때와 같다: 패키지마다 계획·레지스트리·조치안 순서
    assert [p.evidence for p in plans] == [["E-0050", "E-0049", "E-0051"], ["E-0053", "E-0052", "E-0054"],
                                           ["E-0056", "E-0055", "E-0057"], ["E-0059", "E-0058", "E-0060"]]
    assert all(store.get(p.evidence[2]).source == "advice:llm" for p in plans)


@pytest.mark.parametrize("variant", range(len(JACKSON_LINE)))
def test_recorded_version_line_advice_passes_gate(pipeline, monkeypatch, variant):
    store, assets, *_rest, scored, cache = pipeline
    replay(monkeypatch, {**RECORDED, "jackson-databind": JACKSON_LINE[variant]})
    plans = remediate.plan_remediations(scored, store, assets, ROOT, cache, offline=True)
    assert {p.package: p.advice_source for p in plans} == {pkg: "llm" for pkg in RECORDED}


def test_recorded_advice_with_other_version_line_is_rejected(pipeline, monkeypatch):
    store, assets, *_rest, scored, cache = pipeline
    other = copy.deepcopy(JACKSON_LINE[0])
    other["breaking_change_risk"] = other["breaking_change_risk"].replace("2.9.x", "2.10.x")
    replay(monkeypatch, {**RECORDED, "jackson-databind": other})
    plans = remediate.plan_remediations(scored, store, assets, ROOT, cache, offline=True)
    jackson = next(p for p in plans if p.package == "jackson-databind")
    assert jackson.advice_source == "template"
    assert [(x["token"], x["why"]) for x in jackson.fallback["problems"]] == [
        ("2.10.x", "현재·목표 버전이 속하지 않는 버전 라인")]


def test_every_fallback_is_logged_to_rejections_jsonl(tmp_path, monkeypatch):
    cache = tmp_path / "cache"
    shutil.copytree(FIX / "cache", cache)
    tampered = copy.deepcopy(RECORDED)
    tampered["log4j-core"]["steps"].append("여유가 되면 2.18.0으로 한 번 더 올립니다.")

    def fake(payload):
        pkg = payload["package"].split(":")[-1]
        if pkg == "snakeyaml":
            raise RuntimeError("stop_reason=refusal")
        return tampered[pkg]

    monkeypatch.setenv("ANTHROPIC_API_KEY", "replay")
    monkeypatch.setattr(llm, "_ask_claude", fake)
    args = argparse.Namespace(service="order-api", root=str(ROOT), out=str(tmp_path / "out"), cache=str(cache),
                              offline=True, grype=str(FIX / "grype_sample.json"))
    for _ in range(2):                                   # 실행마다 덧붙인다 (지난 기록을 지우지 않음)
        cli.run(args)
    rows = [json.loads(line) for line in (tmp_path / "out" / "rejections.jsonl").read_text().splitlines()]
    assert [(r["package"], r["kind"]) for r in rows] == [("log4j-core", "rejected"), ("snakeyaml", "error")] * 2
    log4j, snakeyaml = rows[:2]
    assert log4j["problems"][0]["token"] == "2.18.0" and log4j["problems"][0]["field"] == "steps[4]"
    assert log4j["output"]["steps"][-1].startswith("여유가 되면 2.18.0")   # Claude 가 쓴 원문도 남긴다
    assert "refusal" in snakeyaml["error"]


def test_generated_evidence_requires_citation():
    s = EvidenceStore()
    with pytest.raises(ValueError):
        s.add("generated", "llm", "x", "근거 없는 문장")


def test_remaining_cves_are_reported(pipeline):
    store, assets, *_rest, scored, cache = pipeline
    plans = remediate.plan_remediations(scored, store, assets, ROOT, cache, offline=True)
    jackson = next(p for p in plans if p.package == "jackson-databind")
    assert jackson.target == "2.9.10.3"
    assert "CVE-2020-36518" in jackson.remaining      # 2.9.10.3 으로는 안 고쳐짐
    log4j = next(p for p in plans if p.package == "log4j-core")
    assert "CVE-2021-45105" in log4j.vulns and not log4j.remaining   # 추적 등급이어도 함께 해소
