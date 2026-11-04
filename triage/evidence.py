"""공유 근거 저장소.

각 단계가 관찰·조회·계산한 사실을 한 줄씩 남긴다. 보고서와 LLM 조치안은 여기 있는 ID만 인용할 수 있다.
kind:
  observed  — 도구가 직접 낸 결과 (SBOM, 스캐너 매칭)
  retrieved — 외부 데이터에서 조회 (EPSS, KEV, 레지스트리)
  derived   — 규칙으로 계산 (점수, 등급, 도달 가능성 판정)
  generated — LLM 이 쓴 문장 (조치안). 반드시 다른 근거를 인용해야 한다
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

KINDS = {"observed", "retrieved", "derived", "generated"}


@dataclass
class Evidence:
    id: str
    kind: str
    source: str
    subject: str
    claim: str
    data: dict[str, Any] = field(default_factory=dict)
    cites: list[str] = field(default_factory=list)


class EvidenceStore:
    def __init__(self) -> None:
        self._items: dict[str, Evidence | None] = {}   # None = reserve 로 자리만 잡고 아직 안 채운 것

    def add(self, kind: str, source: str, subject: str, claim: str,
            data: dict[str, Any] | None = None, cites: list[str] | None = None) -> str:
        eid = f"E-{len(self._items) + 1:04d}"
        self._items[eid] = self._make(eid, kind, source, subject, claim, data, cites)
        return eid

    def reserve(self) -> str:
        """ID 자리만 먼저 잡는다. 조치안을 동시에 만들어도 ID 순서가 순차 실행 때와 같게 하려고 쓴다."""
        eid = f"E-{len(self._items) + 1:04d}"
        self._items[eid] = None
        return eid

    def fill(self, eid: str, kind: str, source: str, subject: str, claim: str,
             data: dict[str, Any] | None = None, cites: list[str] | None = None) -> str:
        if eid not in self._items or self._items[eid] is not None:
            raise ValueError(f"not a reserved evidence id: {eid}")
        self._items[eid] = self._make(eid, kind, source, subject, claim, data, cites)
        return eid

    def _make(self, eid: str, kind: str, source: str, subject: str, claim: str,
              data: dict[str, Any] | None, cites: list[str] | None) -> Evidence:
        if kind not in KINDS:
            raise ValueError(f"unknown evidence kind: {kind}")
        cites = cites or []
        missing = [c for c in cites if not self.has(c)]
        if missing:
            raise ValueError(f"cites unknown evidence: {missing}")
        if kind == "generated" and not cites:
            raise ValueError("generated evidence must cite at least one other evidence")
        return Evidence(eid, kind, source, subject, claim, data or {}, cites)

    def get(self, eid: str) -> Evidence:
        return self._items[eid]

    def has(self, eid: str) -> bool:
        return self._items.get(eid) is not None

    def for_subject(self, subject: str) -> list[Evidence]:
        return [e for e in self._items.values() if e is not None and e.subject == subject]

    def __len__(self) -> int:
        return len(self._items)

    def dump(self, path: Path) -> None:
        with path.open("w", encoding="utf-8") as f:
            for e in self._items.values():
                f.write(json.dumps(asdict(e), ensure_ascii=False) + "\n")
