# 대응 조치 탭 연결 계약

`사건 → 대응 조치 → 파이프라인` 순서로 배치합니다. 전역 대응 화면은 사건 상세와 동일한 `results/response/*_response.json` 산출물을 사용하며, 기존 사건/조사 ID와 파일 stem 연결 방식을 유지합니다.

## 화면과 저장 범위

- 권고 사항: 검색, 서버·유형·기법·상태 필터, 근거·명령·영향·롤백·검증 상세, 사건 상세 이동.
- 적용 현황: 실행 산출물의 상태·결과·시각과 브라우저 검토 기록을 구분해서 표시.
- 통계: 현재 스냅샷의 유형 분포·기법별 권고 수·반복 권고 후보·기법 연결률·검증 성공률·중앙 대응 시간.
- 검토 완료/적용 제외와 메모는 `localStorage`의 `ssoc-response-reviews-v1`에만 저장합니다. 여러 브라우저/사용자 간 공유 승인 기록이 아닙니다. 권고 내용이 변경되면 이전 검토는 무효화합니다.
- 명령 복사와 적용 요청서 JSON 내보내기는 실행하지 않습니다. 서버 실행 API, 실제 승인 처리, 실행 어댑터는 별도 연결이 필요합니다. 현재 L2도 자동 실행 상태로 표시하지 않습니다.

## 추가 지원 필드

기존 필드를 그대로 유지하면서 다음 선택 필드를 정규화합니다. 필드가 없으면 출처·시간·성과를 추정하지 않습니다.

```json
{
  "generated_at": "2026-10-07T00:00:00Z",
  "generator_model": "실제 사용 모델 ID",
  "attack_data": { "version": "19.2" },
  "actions": [{
    "action_id": "act_01",
    "template_id": "안정적인 조치 유형 ID",
    "technique_id": "T1105",
    "technique_ids": ["T1105", "T1059.004"],
    "preconditions": ["적용 전 확인해야 할 실제 조건"],
    "mitigation_sources": [{
      "title": "실제로 참고한 공식 문서 제목",
      "url": "https://attack.mitre.org/mitigations/M1030/",
      "mitigation_id": "M1030",
      "version": "19.2"
    }],
    "execution": {
      "status": "verified",
      "requested_at": "2026-10-07T00:05:00Z",
      "started_at": "2026-10-07T00:10:00Z",
      "completed_at": "2026-10-07T00:12:00Z",
      "verified_at": "2026-10-07T00:20:00Z",
      "actor": "실제 실행 주체",
      "result": "실행 결과",
      "verification_result": "사후 검증 결과"
    }
  }]
}
```

실행 상태는 `requested`, `approved`, `queued`, `running`, `verifying`, `applied`, `succeeded`, `completed`, `verified`, `failed`, `verification_failed`, `rolled_back`, `cancelled`를 지원합니다. `succeeded`/`completed`는 검증 성공으로 처리하지 않으며 `verified`만 검증 완료입니다. 모르는 상태는 실행 상태 미확인으로 표시합니다.

## 집계 규칙

- 권고 식별자: 사건 ID + 조사 ID + 대응 파일 + 조치 ID. 같은 산출물이 중복 노출돼도 한 번만 집계합니다.
- 통합 후보: 서버 + 대상 + 템플릿 ID(없으면 제목) + 명령 참고가 같은 권고. 실제 병합/실행은 하지 않습니다.
- 반복 후보: 통합 후보가 서로 다른 사건 2건 이상에서 발생. 재출력만 반복된 경우에는 후보가 아닙니다.
- 기법 연결률: 필터를 통과한 권고가 연결하는 사건·기법 쌍 / 서버·사건 범위 내 매핑된 사건·기법 쌍. 방어 효과나 커버리지 검증 결과가 아닙니다.
- 검증 성공률: `verified` / (`verified` + `verification_failed`). 실행 중/대기는 분모에서 제외합니다.
- 중앙 대응 시간: `generated_at`부터 `verified_at`까지의 유효한 비음수 간격 중앙값. 사건 발생 시각을 생성 시각 대신 사용하지 않습니다.
- 과거 스냅샷 이력이 없으므로 추이·기간 전환율·SLA 준수율은 표시하지 않습니다.

검증: `node --experimental-strip-types --test scripts/response.test.mjs`
