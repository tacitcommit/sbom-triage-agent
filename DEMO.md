# 데모 영상 (약 1분 25초, 소리 없음)

`./demo.sh` 한 번 실행을 편집 없이 녹화한다. 장면마다 화면을 지우고 핵심 한 줄(자막)을 먼저 띄운 뒤 실제 출력을 보여 준다.
소리 없이 봐도 이해되게 하는 것이 목표다.

## 만들기

```bash
brew install vhs && brew install --cask font-d2coding   # 한 번만 (한글 고정폭 글꼴)
vhs demo.tape             # → docs/demo.mp4 (1920×1080)
ffmpeg -y -i docs/demo.mp4 -vf "fps=8,scale=1280:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=64:stats_mode=diff[p];[b][p]paletteuse=dither=none:diff_mode=rectangle" docs/demo.gif   # README 미리보기 (약 1MB)
```

직접 화면 녹화(⌘⇧5)로 찍어도 된다. 터미널 창을 넓게 열고 `./demo.sh` 를 실행하면 된다.

- 실데이터 실행이라 syft·grype 와 `ANTHROPIC_API_KEY` 가 필요하다. 키가 셸 환경에 없으면 스크립트가 로그인 셸 설정에서 찾는다.
- 숫자(64건, 6건 등)는 grype 취약점 DB 날짜에 따라 바뀐다. 자막의 숫자는 그 실행의 보고서에서 읽어 넣는다.
- 조치안이 템플릿으로 대체되면 표의 `조치안` 칸에 그대로 나오고, 이유는 `out/rejections.jsonl` 에 남는다.
- `FAST=1 ./demo.sh` 는 멈춤 없이 돌려 점검만 한다.

## 장면

| 장면 | 자막 | 화면 |
| --- | --- | --- |
| 시작 | 스캐너 결과 수십 건을 "이번 주 조치할 N건과 그 근거"로 | ①~④ 단계와 LLM 이 맡는 범위 |
| 1 | 인터넷에 노출된 주문 API | `sample-app/pom.xml` 의존성 |
| 2 | 명령 하나로 ①~④ 실행, Claude 는 조치안 문장만 | `python -m triage.cli run --service order-api` |
| 3 | 스캐너 N건 → 이번 주 조치 M건 | 패키지별 현재 → 목표, 해소·남는 CVE, 조치안 검증 결과 |
| 4 | PR 초안까지, 머지는 사람이 | `out/pr-<패키지>-<목표>.patch` |
| 5 | 모든 줄이 근거 ID, Claude 조치안도 근거를 인용 | 조치안 근거 → 인용한 근거(레지스트리·스캐너·EPSS) |
| 6 | 검증 게이트는 테스트로 고정 | `pytest -q` (19개) |
| 끝 | 저장소 링크 | github.com/tacitcommit/sbom-triage-agent |

영상을 만든 뒤: 지원서 포트폴리오 PDF 마지막 장과 AI 역량 칸에 저장소·영상 링크를 한 줄씩 넣는다.
