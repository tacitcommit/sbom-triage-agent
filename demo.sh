#!/usr/bin/env bash
# 포트폴리오용 실행 영상 (DEMO.md). 소리 없이 봐도 이해되게, 장면마다 화면을 지우고
# 핵심 한 줄(자막)을 먼저 띄운 뒤 실제 출력을 보여 주고 읽을 시간만큼 멈춘다. 전체 약 1분 40초.
#   ./demo.sh           # 실데이터 (syft·grype 필요)
#   FAST=1 ./demo.sh    # 멈춤 없이 (점검용)
#   vhs demo.tape       # 이 스크립트를 out/demo.mp4 로 녹화
set -euo pipefail
cd "$(dirname "$0")"
source .venv/bin/activate          # 스크립트 안에서는 셸 alias 가 없어 venv 의 python 을 쓴다

# 앱의 실행 버튼처럼 셸 설정(~/.zshrc 등)을 읽지 않고 시작되면 키가 비어 있다 → 로그인 셸에 한 번 물어본다.
# 셸 시작 메시지가 섞이지 않게 표시를 붙여 받고, 키는 화면에 찍지 않는다.
if [ -z "${ANTHROPIC_API_KEY:-}" ]; then
  ANTHROPIC_API_KEY=$("${SHELL:-/bin/zsh}" -ic 'printf "\n__KEY__%s\n" "${ANTHROPIC_API_KEY:-}"' 2>/dev/null </dev/null \
                      | sed -n 's/^__KEY__//p' || true)
  export ANTHROPIC_API_KEY
fi

hold() { [ -n "${FAST:-}" ] || sleep "$1"; }

scene() {   # scene "자막" ["부연"] — 화면을 지우고 자막부터 띄운다
  printf '\033[2J\033[H'   # clear 와 같음 (TERM 이 없어도 동작)
  printf '\n\033[1;36m%s\033[0m\n' "$1"
  [ -z "${2:-}" ] || printf '\033[36m%s\033[0m\n' "$2"
  echo
  hold 2
}

run() {
  printf '\033[2m$ %s\033[0m\n' "$*"
  "$@"
}

[ -n "${ANTHROPIC_API_KEY:-}" ] || echo "※ ANTHROPIC_API_KEY 가 없어 조치안은 템플릿으로 작성됩니다."

scene "sbom-triage-agent" "스캐너가 찾은 취약점 수십 건을 '이번 주 조치할 N건과 그 근거'로 바꾼다"
cat <<'EOF'
  ① 수집      Syft → SBOM, Grype → 취약점 매칭                       LLM 없음
  ② 맥락      자산(노출·중요도) + 도달 가능성(import·호출 패턴)       LLM 없음
  ③ 우선순위  CVSS + EPSS + KEV + 노출 + 도달 → 이번 주 / 정기 / 추적  규칙만
  ④ 조치      목표 버전 → Maven Central 실재 확인 → PR 초안 → 조치안   LLM 은 문장만

  모든 단계가 근거 저장소에 기록하고, 보고서의 모든 줄이 근거 ID 를 단다.
EOF
hold 6

scene "1. 데모 서비스: 인터넷에 노출된 주문 API (중요도 high)" "알려진 취약 버전을 일부러 넣은 sample-app/pom.xml 의 의존성과 config/assets.yaml 의 자산 맥락"
python - <<'PY'
import xml.etree.ElementTree as ET
from pathlib import Path
from triage.context import load_assets

ns = {"m": "http://maven.apache.org/POM/4.0.0"}
for d in ET.parse("sample-app/pom.xml").getroot().iterfind("m:dependencies/m:dependency", ns):
    g, a, v = (d.findtext(f"m:{k}", namespaces=ns) for k in ("groupId", "artifactId", "version"))
    print(f"  {g + ':' + a:50} {v}")
svc = load_assets(Path("config/assets.yaml"))["order-api"]
print(f"\n  order-api — 노출 {svc['exposure']} · 중요도 {svc['criticality']} · {svc['note']}")
PY
hold 6

scene "2. 명령 하나로 ①~④ 를 실행" "점수·순위·목표 버전은 규칙으로 계산하고, Claude 는 조치안 문장만 쓴다 (패키지별로 동시에 호출)"
run python -m triage.cli run --service order-api
hold 3

read -r total act < <(python -c 'import json; r = json.load(open("out/report.json"))["ranking"]; print(len(r), sum(x["tier"] == "act" for x in r))')
scene "3. 스캐너 ${total}건 → 이번 주 조치 ${act}건" "패키지 단위로 묶고, 모든 CVE 를 고치는 최소 버전이 Maven Central 에 실제로 있을 때만 추천"
python - <<'PY'
import json, unicodedata
from triage.report import TIER_KO

w = lambda s: sum(2 if unicodedata.east_asian_width(c) in "WF" else 1 for c in s)
pad = lambda s, n: s + " " * max(0, n - w(s))
plans = json.load(open("out/report.json"))["plans"]
cols = [("등급", 16), ("패키지", 19), ("현재 → 목표", 23), ("해소", 9), ("남음", 9), ("조치안", 0)]
print("  " + "".join(pad(name, n) for name, n in cols))
print("  " + "─" * 98)
for p in plans:
    row = [TIER_KO[p["tier"]], p["package"], f"{p['current']} → {p['target'] or '판단 불가'}",
           f"{len(p['vulns'])}건", f"{len(p['remaining'])}건" if p["remaining"] else "-",
           "Claude (검증 통과)" if p["advice_source"] == "llm" else "템플릿 (검증 탈락·대체)"]
    print("  " + "".join(pad(v, n) for v, (_, n) in zip(row, cols)))
print()
for p in plans:
    if p["remaining"]:
        print(f"  ※ {p['package']} 는 {p['target']} 로 올려도 {len(p['remaining'])}건이 남는다 — 따로 표시해 추적")
PY
hold 10

patch=$(python -c 'import json; print("out/pr-{package}-{target}.patch".format(**json.load(open("out/report.json"))["plans"][0]))')
scene "4. PR 초안까지 만든다 — 머지는 사람이 승인" "$patch"
run cat "$patch"
hold 5

scene "5. 모든 줄이 근거 ID 를 단다 — Claude 가 쓴 조치안도 근거를 인용한다" "없는 근거 ID 를 인용하거나 근거에 없는 버전을 쓰면 버리고 템플릿으로 대체 (이유는 out/rejections.jsonl)"
python - <<'PY'
import json, shutil, unicodedata

w = lambda s: sum(2 if unicodedata.east_asian_width(c) in "WF" else 1 for c in s)

def cut(s, n):
    out = ""
    for c in s:
        if w(out) + w(c) > n - 1:
            return out + "…"
        out += c
    return out

width = shutil.get_terminal_size((150, 40)).columns - 4
report = json.load(open("out/report.json"))
plan = report["plans"][0]
ev = {e["id"]: e for e in map(json.loads, open("out/evidence.jsonl", encoding="utf-8"))}
adv = ev[plan["evidence"][2]]
print(f"  보고서 {plan['package']} 줄의 근거: {', '.join(plan['evidence'])}\n")
print(f"  {adv['id']}  {adv['kind']} · {adv['source']}")
print(f"  “{cut(adv['claim'], width - 4)}”\n")
print(f"  인용한 근거 {len(adv['cites'])}건 중:")
for c in adv["cites"][:4]:
    e = ev[c]
    print(f"    ↳ {c}  {e['kind']:9} {e['source']:13} {cut(e['claim'], width - 36)}")
print(f"    ↳ … 외 {len(adv['cites']) - 4}건\n")
llm = sum(p["advice_source"] == "llm" for p in report["plans"])
print(f"  이번 실행: Claude 조치안 {llm}/{len(report['plans'])}건 검증 통과")
PY
hold 10

scene "6. 검증 게이트는 테스트로 고정" "지어낸 버전·없는 근거 ID·다른 버전 라인은 탈락 — 기록해 둔 실제 Claude 응답을 재생 (API 호출 없음)"
run pytest -q
hold 4

scene "github.com/tacitcommit/sbom-triage-agent" "이 영상은 ./demo.sh 한 번 실행을 그대로 녹화한 것"
hold 6
