import test from "node:test";
import assert from "node:assert/strict";
import { toResponse } from "./sync-results.mjs";
import { actionFingerprint, currentReview, entryStatus, flattenResponses, responseStatistics, safeSourceUrl } from "../lib/response.ts";

const raw = { response_status: "recommended", generated_at: "2026-10-07T00:00:00Z", actions: [{ action_id: "a1", title: "IP 차단", target: "192.0.2.1", technique_id: "T1105", template_id: "BLOCK", command_hint: "참고 명령", requires_approval: true }] };
const incident = (response) => ({ incidentId: "INC-1", investigationId: "INV-1", sourceFile: "report.json", title: "사건", severity: "HIGH", host: "web-1", timestamp: "2026-10-07T00:00:00Z", response });

test("권고만 있는 데이터는 검증 성과를 만들지 않는다", () => {
  const response = toResponse(raw, "response/INC-1_response.json");
  const entries = flattenResponses([incident(response), incident(response)]);
  assert.equal(entries.length, 1);
  assert.equal(entries[0].action.requiresApproval, true);
  assert.equal(response.generatedAt, raw.generated_at);
  assert.equal(responseStatistics(entries).withExecution.length, 0);
  assert.equal(responseStatistics(entries).median, null);
});

test("다중 기법·공식 출처·실행 결과의 정규화를 보존한다", () => {
  const response = toResponse({ ...raw, actions: [{ ...raw.actions[0], technique_ids: ["T1105", "T1059.004"], mitigation_sources: [{ title: "문서", url: "https://attack.mitre.org/", mitigation_id: "M1030", version: "19.2" }], execution: { status: "verified", verified_at: "2026-10-07T00:20:00Z", verification_result: "통신 차단 확인" } }] }, "response/INC-1_response.json");
  assert.deepEqual(response.actions[0].techniqueIds, ["T1105", "T1059.004"]);
  assert.equal(response.actions[0].mitigationSources[0].mitigationId, "M1030");
  const stats = responseStatistics(flattenResponses([incident(response)]));
  assert.equal(stats.verified.length, 1);
  assert.equal(stats.median, 20);
});

test("검토 기록은 변경된 권고에 재사용되지 않는다", () => {
  const entry = flattenResponses([incident(toResponse(raw, "response/INC-1_response.json"))])[0];
  const reviews = { [entry.key]: { decision: "reviewed", note: "확인", updatedAt: "2026-10-07T00:00:00Z", fingerprint: actionFingerprint(entry) } };
  assert.equal(entryStatus(entry, reviews), "reviewed");
  const changed = { ...entry, action: { ...entry.action, target: "192.0.2.2" } };
  assert.equal(currentReview(changed, reviews), undefined);
  assert.equal(entryStatus(changed, reviews), "review");
});

test("성공 실행과 검증 성공을 분리하고 잘못된 시간은 제외한다", () => {
  const execution = { status: "succeeded", requestedAt: "", startedAt: "", completedAt: "", verifiedAt: "", result: "", verificationResult: "", actor: "" };
  const entries = flattenResponses([incident(toResponse(raw, "response/INC-1_response.json"))]);
  entries[0].action.execution = execution;
  assert.equal(responseStatistics(entries).verified.length, 0);
  entries[0].action.execution = { ...execution, status: "verified", verifiedAt: "2026-10-06T00:00:00Z" };
  assert.equal(responseStatistics(entries).median, null);
  assert.equal(safeSourceUrl("javascript:alert(1)"), null);
  assert.equal(safeSourceUrl("http://example.com"), null);
});
