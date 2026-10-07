// 대응 생성기 산출물과 화면 사이에서 사용하는 공통 계약입니다.
export type ResponseSource = { title: string; url: string; mitigationId: string; version: string };
export type ResponseExecution = {
  status: string;
  requestedAt: string;
  startedAt: string;
  completedAt: string;
  verifiedAt: string;
  result: string;
  verificationResult: string;
  actor: string;
};
export type ResponseAction = {
  id: string; title: string; category: string; categoryLabel: string; priority: number;
  target: string; techniqueId: string; techniqueName: string; tacticName: string;
  risk: string; reversible: boolean; requiresApproval: boolean; reason: string;
  commandHint: string; rollback: string; sideEffects: string; verification: string;
  evidenceIds: string[]; autonomy: string; autonomyLabel: string; autonomyReason: string;
  autonomyDowngradedFrom: string;
  templateId?: string;
  techniqueIds?: string[];
  mitigationSources?: ResponseSource[];
  preconditions?: string[];
  execution?: ResponseExecution | null;
};
export type ResponseData = {
  sourceFile: string; status: string; statusLabel: string; mappingNote: string;
  autonomyLegend?: Record<string, string>;
  summary: string; analystNote: string; remainingUnknowns: string[]; warnings: string[];
  errors: string[]; actions: ResponseAction[];
  generatedAt?: string;
  model?: string;
  attackVersion?: string;
  selectionMode?: string;
};
export type ResponseIncident = {
  incidentId: string; investigationId: string; sourceFile: string; title: string;
  severity: string; host: string; timestamp: string;
  response?: ResponseData | null;
  attackMapping?: { techniques: { id: string }[] } | null;
};
export type ResponseEntry = { key: string; action: ResponseAction; incident: ResponseIncident; response: ResponseData };
export type ReviewRecord = { decision: "reviewed" | "excluded"; note: string; updatedAt: string; fingerprint: string };
export type Reviews = Record<string, ReviewRecord>;
export const reviewStorageKey = "ssoc-response-reviews-v1";

export const riskLabels: Record<string, string> = { LOW: "낮음", MED: "중간", MEDIUM: "중간", HIGH: "높음", CRITICAL: "매우 높음" };
export const executionLabels: Record<string, string> = {
  requested: "적용 요청", approved: "승인됨", queued: "실행 대기", running: "적용 중",
  verifying: "검증 중", applied: "실행 완료 · 미검증", succeeded: "실행 완료 · 미검증",
  completed: "실행 완료 · 미검증", verified: "검증 완료", failed: "실행 실패",
  verification_failed: "검증 실패", rolled_back: "롤백 완료", cancelled: "취소됨",
};
export function safeSourceUrl(value: string): string | null {
  try { const url = new URL(value); return url.protocol === "https:" ? url.href : null; } catch { return null; }
}
export function techniqueUrl(id: string): string | null {
  return /^T\d{4}(\.\d{3})?$/.test(id) ? `https://attack.mitre.org/techniques/${id.replace(".", "/")}/` : null;
}
export function actionTechniques(action: ResponseAction): string[] {
  return [...new Set([action.techniqueId, ...(action.techniqueIds ?? [])].filter(Boolean))];
}
export function actionFingerprint(entry: ResponseEntry): string {
  // 재생성된 명령·대상·근거가 바뀌면 이전 검토 상태를 재사용하지 않습니다.
  return JSON.stringify({ action: entry.action, warnings: entry.response.warnings, errors: entry.response.errors, unknowns: entry.response.remainingUnknowns });
}
export function currentReview(entry: ResponseEntry, reviews: Reviews): ReviewRecord | undefined {
  const review = reviews[entry.key];
  return review?.fingerprint === actionFingerprint(entry) ? review : undefined;
}
export function entryStatus(entry: ResponseEntry, reviews: Reviews): string {
  if (entry.action.execution?.status) return executionLabels[entry.action.execution.status] ? entry.action.execution.status : "execution_unknown";
  const review = currentReview(entry, reviews);
  if (review?.decision === "excluded") return "excluded";
  if (review?.decision === "reviewed") return "reviewed";
  return entry.action.category === "verify_needed" || !entry.action.target ? "needs_details" : "review";
}
export function statusLabel(status: string): string {
  return executionLabels[status] ?? ({ review: "검토 필요", needs_details: "확인 필요", reviewed: "검토 완료", excluded: "적용 제외", execution_unknown: "실행 상태 미확인" }[status] ?? status);
}
export function flattenResponses(incidents: ResponseIncident[]): ResponseEntry[] {
  const entries = new Map<string, ResponseEntry>();
  for (const incident of incidents) {
    const response = incident.response;
    if (!response) continue;
    for (const action of response.actions) {
      const key = JSON.stringify([incident.incidentId, incident.investigationId, response.sourceFile, action.id]);
      if (!entries.has(key)) entries.set(key, { key, action, incident, response });
    }
  }
  const severity: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  return [...entries.values()].sort((a, b) => (severity[a.incident.severity] ?? 4) - (severity[b.incident.severity] ?? 4)
    || (a.action.priority || 99) - (b.action.priority || 99)
    || a.action.id.localeCompare(b.action.id));
}
export function normalizedActionKey(entry: ResponseEntry): string {
  return JSON.stringify([entry.incident.host, entry.action.target, entry.action.templateId || entry.action.title, entry.action.commandHint]);
}
export function responseStatistics(entries: ResponseEntry[]) {
  const withExecution = entries.filter((entry) => entry.action.execution);
  const finished = withExecution.filter((entry) => ["applied", "succeeded", "completed", "verified", "verification_failed", "rolled_back"].includes(entry.action.execution!.status));
  const verificationFinished = withExecution.filter((entry) => ["verified", "verification_failed"].includes(entry.action.execution!.status));
  const verified = verificationFinished.filter((entry) => entry.action.execution!.status === "verified");
  const durations = verified.flatMap((entry) => {
    const start = Date.parse(entry.response.generatedAt || "");
    const end = Date.parse(entry.action.execution!.verifiedAt);
    return Number.isFinite(start) && Number.isFinite(end) && end >= start ? [(end - start) / 60_000] : [];
  }).sort((a, b) => a - b);
  const middle = Math.floor(durations.length / 2);
  const median = durations.length ? durations.length % 2 ? durations[middle] : (durations[middle - 1] + durations[middle]) / 2 : null;
  return { withExecution, finished, verified, verificationFinished, median, durationSamples: durations.length };
}
