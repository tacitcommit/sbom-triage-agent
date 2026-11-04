"""조치안 문장 생성. LLM 은 설명만 쓴다 — 점수·버전·순위는 바꾸지 못한다.

검증 규칙 (하나라도 어기면 템플릿으로 대체):
  - cited_evidence 는 입력으로 준 근거 ID 의 부분집합이어야 한다
  - 본문에 나오는 버전·숫자는 현재 버전, (확인된) 목표 버전, 실제로 인용한 근거 문장에 있는 숫자뿐이어야 한다
  - 레지스트리에 있는 이 패키지의 다른 버전은 인용한 근거에 있더라도 본문에 나오면 안 된다
  - "2.9.x" 같은 버전 라인은 현재·목표 버전이 그 라인에 속할 때만 쓸 수 있다
ANTHROPIC_API_KEY 가 없으면 처음부터 템플릿을 쓴다. 대체한 이유는 write_advice 의 세 번째 반환값으로 넘긴다.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Iterable

SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["summary", "steps", "breaking_change_risk", "interim_mitigation", "cited_evidence"],
    "properties": {
        "summary": {"type": "string"},
        "steps": {"type": "array", "items": {"type": "string"}},
        "breaking_change_risk": {"type": "string"},
        "interim_mitigation": {"type": "string"},
        "cited_evidence": {"type": "array", "items": {"type": "string"}},
    },
}

SYSTEM = (
    "너는 보안 담당자를 돕는 조치안 작성자다. 주어진 근거만 사용한다. "
    "새 버전 번호를 만들어 내지 말고, 목표 버전이 null 이면 버전 업을 권하지 말고 '확인된 수정 버전 없음'이라고 쓴다. "
    "버전 라인을 말할 때는 '2.25.x'처럼 x 를 붙여 쓰고, '2.25'처럼 맨 숫자로 줄여 쓰지 않는다. "
    "점수나 등급을 바꾸거나 새로 매기지 않는다. 한국어로, 담당자가 바로 실행할 수 있게 짧게 쓴다. "
    "cited_evidence 에는 실제로 근거로 쓴 ID 만 넣는다."
)

# 점으로 이어진 숫자(버전·점수). "2.14.1을" 처럼 조사가 붙어도, "2.18.0." 처럼 마침표로 끝나도 끝까지 읽는다.
# "2.9.x"·"1.x" 같은 버전 라인은 끝의 x 까지 한 토큰으로 읽는다 ("2.9" 로 잘라 읽지 않게)
VERSION_RE = re.compile(r"(?<![\d.])(?:\d+(?:\.\d+){0,3}\.[xX*](?![A-Za-z0-9])|\d+(?:\.\d+){1,3}(?!\.?\d))")
ID_RE = re.compile(r"CVE-\d{4}-\d+|GHSA-[\w-]+|E-\d{4}")


def template(package: str, current: str, target: str | None, major_bump: bool | None,
             vulns: list[str], evidence: dict[str, str]) -> dict:
    ids = list(evidence)[:2]
    if target:
        return {
            "summary": f"{package} {current} → {target} 업그레이드로 {', '.join(vulns)} 를 해소한다.",
            "steps": [f"pom.xml 의 {package} 버전을 {target} 으로 변경 (PR 초안 참고)",
                      "단위·통합 테스트 실행", "스테이징 배포 후 재스캔으로 해소 확인"],
            "breaking_change_risk": "메이저 버전 변경 — 릴리스 노트 확인 필요" if major_bump else "같은 메이저 버전 내 변경",
            "interim_mitigation": "배포 전까지 해당 기능 입력 검증·WAF 규칙 강화",
            "cited_evidence": ids,
        }
    return {
        "summary": f"{package} {current}: 확인된 수정 버전 없음. 버전 업 조치안은 판단 불가.",
        "steps": ["벤더 권고·대체 라이브러리 검토", "영향 기능 사용 여부를 코드에서 확인"],
        "breaking_change_risk": "판단 불가",
        "interim_mitigation": "해당 기능 비활성화 또는 입력 차단 검토",
        "cited_evidence": ids,
    }


def _numbers(text: str) -> set[str]:
    # CVE 번호(CVE-2021-44228)와 근거 ID(E-0012)는 버전으로 오인하지 않게 지우고 찾는다
    return set(VERSION_RE.findall(ID_RE.sub("", text)))


def _why(token: str, allowed_versions: set[str], grounded: set[str], others: set[str]) -> str | None:
    # 레지스트리에 있는 이 패키지의 다른 버전은 근거에 있어도 쓰면 안 된다
    if token in others:
        return "레지스트리에 있는 이 패키지의 다른 버전"
    # 버전 라인은 현재·목표 버전이 그 라인에 있을 때만 ("2.9.x" → 2.9.10.1 은 "2.9." 로 시작)
    if token[-1] in "xX*":
        if any(v.startswith(token[:-1]) for v in allowed_versions):
            return None
        return "현재·목표 버전이 속하지 않는 버전 라인"
    # 나머지 숫자(CVSS·EPSS·점수 등)는 실제로 인용한 근거 문장에 그대로 있어야 한다
    if token in allowed_versions or token in grounded:
        return None
    return "현재·목표 버전도 아니고 인용한 근거에도 없는 숫자"


def _problems(advice: dict, evidence: dict[str, str], allowed_versions: set[str],
              registry_versions: Iterable[str] = ()) -> list[dict]:
    """검증 규칙을 어긴 곳을 모두 돌려준다 (어느 칸의 어떤 토큰이 왜 걸렸는지). 빈 목록이면 통과."""
    cited = advice.get("cited_evidence") or []
    problems = [{"field": "cited_evidence", "token": c, "why": "입력으로 준 근거에 없는 ID"}
                for c in cited if c not in evidence]
    if not cited:
        problems.append({"field": "cited_evidence", "token": None, "why": "인용한 근거가 없음"})
    grounded = _numbers(" ".join(evidence[c] for c in cited if c in evidence))
    others = set(registry_versions) - allowed_versions
    fields = {"summary": advice["summary"], "breaking_change_risk": advice["breaking_change_risk"],
              "interim_mitigation": advice["interim_mitigation"],
              **{f"steps[{i}]": step for i, step in enumerate(advice["steps"])}}
    for field, text in fields.items():
        for token in sorted(_numbers(text)):
            why = _why(token, allowed_versions, grounded, others)
            if why:
                problems.append({"field": field, "token": token, "why": why})
    return problems


def _valid(advice: dict, evidence: dict[str, str], allowed_versions: set[str],
           registry_versions: Iterable[str] = ()) -> bool:
    return not _problems(advice, evidence, allowed_versions, registry_versions)


def _ask_claude(payload: dict) -> dict:
    import anthropic
    client = anthropic.Anthropic()
    # temperature 는 보내지 않는다 (현재 모델은 거부). 출력 흔들림은 검증 게이트가 막는다.
    # CVE 문장이 안전 분류기에 걸리면 fallbacks="default" 가 서버에서 다른 모델로 재시도한다.
    resp = client.beta.messages.create(
        model=os.environ.get("ANTHROPIC_MODEL", "claude-opus-5-5"),
        max_tokens=16000,
        system=SYSTEM,
        messages=[{"role": "user", "content": json.dumps(payload, ensure_ascii=False)}],
        output_config={"effort": "medium", "format": {"type": "json_schema", "schema": SCHEMA}},
        betas=["server-side-fallback-2026-07-01"],
        fallbacks="default",
    )
    if resp.stop_reason != "end_turn":   # refusal·max_tokens 면 JSON 이 온전하지 않다
        raise RuntimeError(f"stop_reason={resp.stop_reason}")
    return json.loads([b.text for b in resp.content if b.type == "text"][-1])


def write_advice(package: str, group: str | None, current: str, target: str | None,
                 major_bump: bool | None, vulns: list[str], evidence: dict[str, str],
                 registry_versions: Iterable[str] = ()) -> tuple[dict, str, dict | None]:
    """(조치안, "llm"|"template", 템플릿으로 대체한 이유). 키가 없어 처음부터 템플릿이면 이유는 None."""
    fallback = template(package, current, target, major_bump, vulns, evidence)
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return fallback, "template", None
    payload = {"package": f"{group}:{package}" if group else package, "current_version": current,
               "target_version": target, "major_bump": major_bump, "vulnerabilities": vulns,
               "evidence": evidence}
    try:
        advice = _ask_claude(payload)
    except Exception as e:  # 네트워크·모델 오류는 템플릿으로
        fallback["llm_error"] = str(e)[:200]
        return fallback, "template", {"kind": "error", "error": str(e)[:2000]}
    allowed = {current} | ({target} if target else set())
    problems = _problems(advice, evidence, allowed, registry_versions)
    if problems:
        fallback["llm_rejected"] = True
        # 나중에 원인을 볼 수 있게 걸린 토큰과 Claude 가 실제로 쓴 원문을 같이 넘긴다
        return fallback, "template", {"kind": "rejected", "problems": problems, "output": advice}
    return advice, "llm", None
