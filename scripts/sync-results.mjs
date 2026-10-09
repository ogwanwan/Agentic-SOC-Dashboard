import { mkdir, readdir, readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";
import { loadEnvFile } from "node:process";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const projectDir = path.resolve(scriptDir, "..");
const resultsDirFromProcess = process.env.SSOC_RESULTS_DIR;
const dbPathFromProcess = process.env.SSOC_DB_PATH;

try {
  loadEnvFile(path.join(projectDir, ".env"));
} catch (error) {
  if (error?.code !== "ENOENT") throw error;
}

// 셸이나 배포 환경에서 직접 지정한 값이 로컬 .env 설정보다 우선합니다.
if (resultsDirFromProcess !== undefined) process.env.SSOC_RESULTS_DIR = resultsDirFromProcess;
if (dbPathFromProcess !== undefined) process.env.SSOC_DB_PATH = dbPathFromProcess;

const configuredResultsDir = process.env.SSOC_RESULTS_DIR?.trim();
const defaultInputDir = path.join(projectDir, "results");
export const inputDir = configuredResultsDir
  ? path.resolve(projectDir, configuredResultsDir)
  : defaultInputDir;
// 1차 탐지 incident DB(soc.db). 지정하지 않으면 DB 기능 없이 조사 결과만 보여 줍니다.
const configuredDbPath = process.env.SSOC_DB_PATH?.trim();
export const dbPath = configuredDbPath ? path.resolve(projectDir, configuredDbPath) : null;
const outputDir = path.join(projectDir, "data");
const outputPath = path.join(outputDir, "incidents.generated.json");
const publicOutputDir = path.join(projectDir, "public", "data");
const publicOutputPath = path.join(publicOutputDir, "incidents.generated.json");

const cleanText = (value, fallback = "-") =>
  typeof value === "string" && value.trim() ? value.trim() : fallback;

const optionalText = (value) =>
  typeof value === "string" ? value.trim() : "";

const asArray = (value) => (Array.isArray(value) ? value : []);

// 파이프라인 결과 폴더(results/)를 가리키면 하위 단계 폴더도 함께 읽습니다.
// attack_mapping/ 의 *_final_report.json 은 조사 결과 + ATT&CK 매핑 최종본입니다.
const STAGE_DIRS = ["attack_mapping", "investigation_agent"];
const RESPONSE_DIR = "response";
const MAPPING_ONLY_SUFFIX = "_attack_mapping.json";

export const toResponse = (result, sourceFile) => {
  if (!result || typeof result !== "object") return null;
  const display = result.display && typeof result.display === "object" ? result.display : {};
  const autonomyLegend = display.autonomy_legend && typeof display.autonomy_legend === "object"
    ? display.autonomy_legend
    : {};
  const categoryLabels = display.category_labels && typeof display.category_labels === "object"
    ? display.category_labels
    : {};

  return {
    sourceFile,
    status: cleanText(result.response_status, "unknown"),
    statusLabel: cleanText(display.status_label, "대응 권고"),
    autonomyLegend: Object.fromEntries(
      Object.entries(autonomyLegend).map(([level, label]) => [level, cleanText(label, level)]),
    ),
    mappingNote: optionalText(display.mapping_note),
    summary: optionalText(result.summary),
    generatedAt: optionalText(result.generated_at),
    model: optionalText(result.generator_model),
    attackVersion: optionalText(result.attack_data?.version),
    selectionMode: optionalText(result.selection_meta?.mode),
    analystNote: optionalText(result.analyst_note),
    remainingUnknowns: asArray(result.remaining_unknowns).map(String),
    warnings: asArray(result.warnings).map(String),
    errors: asArray(result.errors).map(String),
    actions: asArray(result.actions).map((action, index) => {
      const autonomy = optionalText(action.autonomy);
      const category = cleanText(action.category, "other");
      return {
        id: cleanText(action.action_id, `action-${index + 1}`),
        title: cleanText(action.title, "이름 없는 권고 조치"),
        category,
        categoryLabel: cleanText(categoryLabels[category], category),
        priority: Number(action.priority ?? 0),
        target: optionalText(action.target),
        techniqueId: optionalText(action.technique_id),
        techniqueIds: [...new Set([optionalText(action.technique_id), ...asArray(action.technique_ids).map(String)].filter(Boolean))],
        templateId: optionalText(action.template_id),
        mitigationSources: asArray(action.mitigation_sources).map((source) => ({
          title: cleanText(source.title, "완화 문서"),
          url: optionalText(source.url),
          mitigationId: optionalText(source.mitigation_id),
          version: optionalText(source.version),
        })),
        preconditions: asArray(action.preconditions).map(String),
        execution: action.execution && typeof action.execution === "object" && optionalText(action.execution.status) ? {
          status: optionalText(action.execution.status),
          requestedAt: optionalText(action.execution.requested_at),
          startedAt: optionalText(action.execution.started_at),
          completedAt: optionalText(action.execution.completed_at),
          verifiedAt: optionalText(action.execution.verified_at),
          result: optionalText(action.execution.result),
          verificationResult: optionalText(action.execution.verification_result),
          actor: optionalText(action.execution.actor),
        } : null,
        techniqueName: optionalText(action.technique_name),
        tacticName: optionalText(action.tactic_name),
        risk: optionalText(action.risk),
        reversible: Boolean(action.reversible),
        requiresApproval: Boolean(action.requires_approval),
        reason: optionalText(action.reason) || optionalText(action.default_reason),
        commandHint: optionalText(action.command_hint),
        rollback: optionalText(action.rollback),
        sideEffects: optionalText(action.side_effects),
        verification: optionalText(action.verification),
        evidenceIds: asArray(action.evidence_ids).map(String),
        autonomy,
        autonomyLabel: autonomy ? cleanText(autonomyLegend[autonomy], autonomy) : "",
        autonomyReason: optionalText(action.autonomy_reason),
        autonomyDowngradedFrom: optionalText(action.autonomy_downgraded_from),
      };
    }),
  };
};

// 매핑 결과만 담긴 파일(조사 판정 없음)은 사건이 아니므로 건너뜁니다.
const isMappingOnly = (raw) =>
  raw && typeof raw === "object" && !raw.final_verdict && "mapping_status" in raw;

// 증거 ID → ATT&CK 매핑에서의 쓰임(매핑됨·제외·매칭 없음)
const evidenceMappingIndex = (mapping) => {
  if (!mapping || typeof mapping !== "object") return null;
  const index = new Map();
  for (const technique of asArray(mapping.techniques)) {
    for (const id of asArray(technique.evidence_ids)) {
      const entry = index.get(id) ?? { state: "mapped", techniques: [], reasons: [] };
      entry.techniques.push(cleanText(technique.technique_id, "?"));
      index.set(id, entry);
    }
  }
  for (const item of asArray(mapping.exclusions)) {
    if (!index.has(item.evidence_id)) {
      index.set(item.evidence_id, { state: "excluded", techniques: [], reasons: asArray(item.reasons) });
    }
  }
  for (const id of asArray(mapping.unmatched_evidence_ids)) {
    if (!index.has(id)) index.set(id, { state: "unmatched", techniques: [], reasons: [] });
  }
  return index;
};

const toAttackMapping = (mapping) => {
  if (!mapping || typeof mapping !== "object") return null;
  const selectedByUnit = new Map();
  for (const item of asArray(mapping.techniques)) {
    for (const selection of asArray(item.selections)) {
      const list = selectedByUnit.get(selection.mapping_unit_id) ?? [];
      list.push(item.technique_id);
      selectedByUnit.set(selection.mapping_unit_id, list);
    }
  }
  return {
    status: cleanText(mapping.mapping_status, "unknown"),
    method: cleanText(mapping.mapping_method, "rule"),
    attackVersion: cleanText(mapping.attack_version, ""),
    retrievalVersion: cleanText(mapping.retrieval_version, ""),
    techniques: asArray(mapping.techniques).map((item) => ({
      id: cleanText(item.technique_id, "?"),
      name: cleanText(item.technique_name, ""),
      tactic: cleanText(item.tactic_name, "-"),
      parent: item.parent_technique
        ? `${cleanText(item.parent_technique.technique_id, "")} ${cleanText(item.parent_technique.technique_name, "")}`.trim()
        : "",
      evidenceIds: asArray(item.evidence_ids),
      reasons: asArray(item.selections).map((selection) => ({
        evidenceIds: asArray(selection.evidence_ids),
        reason: cleanText(selection.reason, ""),
      })),
    })),
    killChain: asArray(mapping.kill_chain).map((step) => ({
      step: Number(step.step ?? 0),
      tactic: cleanText(step.tactic_name, "-"),
      techniqueId: cleanText(step.technique_id, "?"),
      techniqueName: cleanText(step.technique_name, ""),
      time: cleanText(step.time, ""),
      evidenceIds: asArray(step.evidence_ids),
    })),
    trace: asArray(mapping.retrieval_trace).map((unit) => ({
      evidenceId: cleanText(unit.mapping_unit_id, "").replace(/^UNIT-/, ""),
      candidates: asArray(unit.candidate_ids),
      selected: selectedByUnit.get(unit.mapping_unit_id) ?? [],
    })),
    exclusions: asArray(mapping.exclusions).map((item) => ({
      evidenceId: cleanText(item.evidence_id, "?"),
      reasons: asArray(item.reasons),
    })),
    unmatched: asArray(mapping.unmatched_evidence_ids),
    rejected: asArray(mapping.rejected_selections).map((item) => ({
      evidenceId: cleanText(item.mapping_unit_id, "").replace(/^UNIT-/, ""),
      value: cleanText(item.value, ""),
      code: cleanText(item.code, ""),
    })),
    errors: asArray(mapping.errors).map((item) => String(item)),
  };
};

const toIncident = (result, sourceFile) => {
  const verdict = result.final_verdict ?? {};
  const seed = result.initial_seed ?? {};
  const stats = result.statistics ?? {};
  const provenance = result.provenance ?? {};
  const mappingIndex = evidenceMappingIndex(result.attack_mapping);
  const mappingOf = (id, contradicting) => {
    if (!mappingIndex) return null;
    if (contradicting) return { state: "context", techniques: [], reasons: [] };
    return mappingIndex.get(id) ?? { state: "unknown", techniques: [], reasons: [] };
  };

  return {
    sourceFile,
    incidentKey: cleanText(result.incident_key, ""),
    incidentId: cleanText(result.incident_id, "UNKNOWN"),
    investigationId: cleanText(result.investigation_id, result.incident_id ?? "UNKNOWN"),
    status: cleanText(result.investigation_status, "COMPLETE"),
    timestamp: cleanText(result.timestamp, seed.trigger_time ?? ""),
    triggerTime: cleanText(seed.trigger_time, result.timestamp ?? ""),
    window: Array.isArray(seed.window) ? seed.window : [],
    title: cleanText(verdict.attack_type, seed.trigger_description ?? "분류되지 않은 사건"),
    summary: cleanText(verdict.summary, seed.trigger_description ?? "요약 없음"),
    reasoning: cleanText(verdict.reasoning, "상세 판정 근거가 기록되지 않았습니다."),
    verdict: cleanText(verdict.verdict, "INCONCLUSIVE"),
    severity: cleanText(verdict.severity, "UNKNOWN"),
    verdictConfidence: Number(verdict.confidence ?? 0),
    investigationConfidence: Number(stats.investigation_confidence ?? 0),
    affectedSystems: Array.isArray(verdict.affected_systems) ? verdict.affected_systems : [],
    host: cleanText(seed.host, "미확인"),
    srcIp: cleanText(seed.src_ip, "-") ,
    priority: Number(seed.priority ?? 999),
    triggerDescription: cleanText(seed.trigger_description, "탐지 설명 없음"),
    detectionSource: cleanText(seed.detection_source, "investigation_pipeline"),
    provenance: {
      status: cleanText(provenance.status, "unavailable"),
      rawRefCount: Number(provenance.raw_ref_count ?? 0),
      evidenceWithoutRawRefs: Array.isArray(provenance.evidence_without_raw_refs)
        ? provenance.evidence_without_raw_refs
        : [],
      issueCount: Array.isArray(provenance.issues) ? provenance.issues.length : 0,
    },
    evidence: (Array.isArray(result.evidence_chain) ? result.evidence_chain : []).map((item) => ({
      id: cleanText(item.evidence_id, `EVID-${item.sequence ?? "?"}`),
      sequence: Number(item.sequence ?? 0),
      time: cleanText(item.time, ""),
      layer: cleanText(item.layer, "unknown"),
      eventType: cleanText(item.event_type, "event"),
      description: cleanText(item.description, "증거 설명 없음"),
      sourceLog: cleanText(item.source_log, "unknown"),
      rawRefs: Array.isArray(item.raw_refs) ? item.raw_refs : [],
      contribution: Number(item.confidence_contribution ?? 0),
      stance: "supporting",
      mapping: mappingOf(item.evidence_id, false),
    })),
    contradictingEvidence: (
      Array.isArray(result.contradicting_evidence) ? result.contradicting_evidence : []
    ).map((item) => ({
      id: cleanText(item.evidence_id, `EVID-${item.sequence ?? "?"}`),
      sequence: Number(item.sequence ?? 0),
      time: cleanText(item.time, ""),
      layer: cleanText(item.layer, "unknown"),
      eventType: cleanText(item.event_type, "event"),
      description: cleanText(item.description ?? item.explanation, "반박 증거 설명 없음"),
      sourceLog: cleanText(item.source_log, "unknown"),
      rawRefs: Array.isArray(item.raw_refs) ? item.raw_refs : [],
      contribution: -Math.abs(Number(item.confidence_reduction ?? 0)),
      stance: "contradicting",
      mapping: mappingOf(item.evidence_id, true),
    })),
    timeline: (Array.isArray(result.attack_timeline) ? result.attack_timeline : []).map((item) => ({
      time: cleanText(item.time, ""),
      event: cleanText(item.event, "사건 관측"),
      source: cleanText(item.source, ""),
    })),
    unknowns: Array.isArray(result.remaining_unknowns) ? result.remaining_unknowns : [],
    notes: Array.isArray(result.investigation_notes) ? result.investigation_notes : [],
    tools: (Array.isArray(result.tools_called) ? result.tools_called : []).map((item) => ({
      sequence: Number(item.sequence ?? 0),
      name: cleanText(item.tool_name, "unknown_tool"),
      resultCount: Number(item.result_count ?? 0),
      summary: cleanText(item.result_summary, "결과 요약 없음"),
      queriedLayers: Array.isArray(item.queried_layers) ? item.queried_layers : [],
      success: !item.error,
    })),
    statistics: {
      toolCalls: Number(stats.tool_calls_count ?? 0),
      evidenceCount: Number(stats.evidence_count ?? 0),
      contradictingEvidenceCount: Number(stats.contradicting_evidence_count ?? 0),
      terminationReason: cleanText(stats.termination_reason, "unknown"),
    },
    attackMapping: toAttackMapping(result.attack_mapping),
  };
};

// 입력 폴더 + (있으면) 단계 폴더의 JSON 파일 목록. 표시 이름은 입력 폴더 기준 상대 경로입니다.
export async function listResultFiles() {
  const directories = [inputDir, ...STAGE_DIRS.map((name) => path.join(inputDir, name))];
  const files = [];
  for (const [index, directory] of directories.entries()) {
    let names;
    try {
      names = await readdir(directory);
    } catch (error) {
      if (index === 0) throw error; // 입력 폴더 자체가 없으면 호출한 쪽에서 처리합니다.
      continue;
    }
    for (const name of names.sort()) {
      if (!name.endsWith(".json") || name.endsWith(MAPPING_ONLY_SUFFIX)) continue;
      files.push(path.relative(inputDir, path.join(directory, name)).split(path.sep).join("/"));
    }
  }
  return files;
}

// 대응 산출물은 사건 최종 보고서와 같은 파일 stem을 사용합니다.
// 예: attack_mapping/INC-123_final_report.json ↔ response/INC-123_response.json
export async function listResponseFiles() {
  const directory = path.join(inputDir, RESPONSE_DIR);
  try {
    return (await readdir(directory))
      .filter((name) => name.endsWith("_response.json"))
      .sort()
      .map((name) => `${RESPONSE_DIR}/${name}`);
  } catch (error) {
    if (error?.code === "ENOENT") return [];
    throw error;
  }
}

const responseStem = (file) => path.basename(file)
  .replace(/_final_report\.json$/, "")
  .replace(/_response\.json$/, "");

// --- 1차 탐지 DB(soc.db) ----------------------------------------------------------
// 파이프라인(detection_pipeline/store/incidents.py)이 5분마다 쓰는 DB를 읽기 전용으로 엽니다.
// 상태 구분은 파이프라인 조사 대기열 조건(QUEUE_WHERE)과 같은 기준입니다.

const parseJson = (text, fallback) => {
  try {
    return text ? JSON.parse(text) : fallback;
  } catch {
    return fallback;
  }
};

const detectionState = (row) => {
  // state.json 에서 옮겨 온 예전 기록은 route·우선순위·상세가 비어 있습니다(다음 새 활동 때 채워짐).
  if (row.route === null || row.route === undefined) return "legacy";
  if (row.route !== "investigate") return "not_targeted"; // P3·P4: 조사 대상이 아님
  if (row.status === "done") return "done";
  if (row.status === "investigating") return "investigating";
  if (row.llm_investigate === 0) return "llm_filtered"; // Haiku 오탐 의견 → 대기열에서 제외
  return "queued";
};

const toDetection = (row) => {
  const extra = parseJson(row.extra_json, {});
  const seeds = asArray(parseJson(row.seeds, []));
  return {
    incidentKey: cleanText(row.incident_key, ""),
    incidentId: cleanText(row.incident_id, ""),
    entityType: cleanText(row.entity_type, ""),
    entityValue: cleanText(row.entity_value, "-"),
    window: [cleanText(row.window_start, ""), cleanText(row.window_end, "")],
    layers: [...new Set(asArray(parseJson(row.layers, [])))].sort(),
    memberCount: Number(row.member_count ?? 0),
    priority: cleanText(row.priority, "-"),
    score: Number(row.triage_score ?? 0),
    parts: extra.triage_parts
      ? {
          severity: Number(extra.triage_parts.severity ?? 0),
          layers: Number(extra.triage_parts.layers ?? 0),
          joinTypes: Number(extra.triage_parts.join_types ?? 0),
          seedCount: Number(extra.triage_parts.seed_count ?? 0),
        }
      : null,
    route: cleanText(row.route, "-"),
    llmInvestigate: row.llm_investigate === null || row.llm_investigate === undefined ? null : Boolean(row.llm_investigate),
    llmReason: cleanText(row.llm_reason, ""),
    state: detectionState(row),
    hasUpdate: Boolean(row.has_update),
    firstDetected: cleanText(row.first_emitted, ""),
    updatedAt: cleanText(row.updated_at, ""),
    rules: [...new Set(seeds.map((seed) => cleanText(seed.reason, "")).filter(Boolean))],
    ruleCount: seeds.length,
    // 아래 두 값은 조사 결과와 연결한 뒤 채웁니다.
    investigated: false,
    resultKey: "",
  };
};

async function loadDetections() {
  if (!dbPath) return { enabled: false, connected: false, error: "", rows: [] };
  let DatabaseSync;
  try {
    ({ DatabaseSync } = await import("node:sqlite"));
  } catch {
    return { enabled: true, connected: false, error: "이 Node.js는 내장 SQLite(node:sqlite)를 지원하지 않습니다(22.13 이상 필요).", rows: [] };
  }
  let db;
  try {
    db = new DatabaseSync(dbPath, { readOnly: true });
    const rows = db.prepare(`
      SELECT i.incident_key, i.incident_id, i.entity_type, i.entity_value, i.window_start, i.window_end,
             i.member_count, i.triage_score, i.priority, i.route, i.llm_investigate, i.llm_reason,
             i.status, i.has_update, i.first_emitted, i.updated_at,
             d.layers, d.seeds, d.extra_json
      FROM incidents i LEFT JOIN incident_details d ON d.incident_key = i.incident_key
      ORDER BY i.updated_at DESC, i.triage_score DESC, i.incident_key ASC`).all();
    return { enabled: true, connected: true, error: "", rows };
  } catch (error) {
    // 파이프라인이 쓰는 중이라 잠깐 잠긴 경우는 기존 스냅샷을 유지하고 감시기가 다시 시도하게 합니다.
    if (/locked|busy/i.test(String(error.message))) {
      throw new Error("incident DB가 잠시 사용 중이라 동기화를 보류했습니다.");
    }
    // 경로가 틀렸거나 파일이 없으면 DB 기능만 끄고 조사 결과는 계속 보여 줍니다.
    return { enabled: true, connected: false, error: `DB를 읽지 못했습니다: ${error.message}`, rows: [] };
  } finally {
    db?.close();
  }
}

// DB 사건과 조사 결과를 incident_key(없으면 incident_id)로 잇고, 탐지→판정 단계별 처리 현황 숫자를 만듭니다.
function buildPipeline(loaded, incidents) {
  const detections = loaded.rows.map(toDetection);
  const byKey = new Map(detections.filter((item) => item.incidentKey).map((item) => [item.incidentKey, item]));
  const byId = new Map(detections.filter((item) => item.incidentId).map((item) => [item.incidentId, item]));
  let linked = 0;
  for (const incident of incidents) {
    const detection = (incident.incidentKey && byKey.get(incident.incidentKey)) || byId.get(incident.incidentId);
    incident.triage = detection
      ? {
          priority: detection.priority, score: detection.score, parts: detection.parts,
          llmInvestigate: detection.llmInvestigate, llmReason: detection.llmReason,
          firstDetected: detection.firstDetected, updatedAt: detection.updatedAt,
          rules: detection.rules, layers: detection.layers,
        }
      : null;
    if (detection) {
      linked += 1;
      detection.investigated = true;
      detection.resultKey = `${incident.sourceFile}::${incident.investigationId}`;
      // 대기열 폴러를 거치지 않고 조사하면 결과는 있어도 DB 상태가 pending 으로 남습니다.
      if (!["done", "investigating"].includes(detection.state)) detection.state = "result_unmarked";
    }
  }
  const count = (predicate) => detections.filter(predicate).length;
  const results = (predicate) => incidents.filter(predicate).length;
  return {
    enabled: loaded.enabled,
    connected: loaded.connected,
    error: loaded.error,
    linked,
    funnel: {
      // 예전 기록은 트리아지 정보가 없어 처리 현황에서 빼고 건수만 따로 보여 줍니다.
      detected: count((d) => d.state !== "legacy"),
      legacy: count((d) => d.state === "legacy"),
      byPriority: Object.fromEntries(["P1", "P2", "P3", "P4"].map((p) => [p, count((d) => d.priority === p)])),
      targeted: count((d) => d.route === "investigate"),
      llmFiltered: count((d) => d.state === "llm_filtered"),
      queued: count((d) => d.state === "queued"),
      investigating: count((d) => d.state === "investigating"),
      resultUnmarked: count((d) => d.state === "result_unmarked"),
      investigated: incidents.length,
      threat: results((i) => i.verdict === "THREAT_CONFIRMED"),
      falsePositive: results((i) => i.verdict === "FALSE_POSITIVE"),
      inconclusive: results((i) => i.verdict === "INCONCLUSIVE"),
      mapped: results((i) => (i.attackMapping?.techniques?.length ?? 0) > 0),
    },
    detections,
  };
}

// 같은 사건(incident_key, 없으면 incident_id)을 다시 조사한 결과는 가장 최근 것 하나만 남깁니다.
// 조사 시각이 같으면 ATT&CK 매핑이 붙은 최종 보고서를 우선합니다.
function latestPerIncident(incidents) {
  const best = new Map();
  for (const incident of incidents) {
    const key = incident.incidentKey || incident.incidentId;
    const current = best.get(key);
    const rank = [String(incident.timestamp), incident.attackMapping ? 1 : 0];
    const currentRank = current && [String(current.timestamp), current.attackMapping ? 1 : 0];
    if (!current || rank[0] > currentRank[0] || (rank[0] === currentRank[0] && rank[1] > currentRank[1])) {
      best.set(key, incident);
    }
  }
  return [...best.values()];
}

async function writeJsonAtomically(targetPath, contents) {
  const temporaryPath = `${targetPath}.${process.pid}.tmp`;
  await writeFile(temporaryPath, contents, "utf8");
  await rename(temporaryPath, targetPath);
}

async function writeJsonIfChanged(targetPath, contents) {
  try {
    if (await readFile(targetPath, "utf8") === contents) return false;
  } catch {
    // 파일이 아직 없으면 아래에서 새로 만듭니다.
  }
  await writeJsonAtomically(targetPath, contents);
  return true;
}

async function readMatchingSnapshot(paths, source, incidents, pipeline, operations) {
  const expected = JSON.stringify({ source, incidents, pipeline, operations });
  for (const candidatePath of paths) {
    try {
      const candidate = JSON.parse(await readFile(candidatePath, "utf8"));
      if (
        typeof candidate.generatedAt === "string"
        && JSON.stringify({ source: candidate.source, incidents: candidate.incidents, pipeline: candidate.pipeline, operations: candidate.operations ?? null }) === expected
      ) return candidate;
    } catch {
      // 다른 후보 스냅샷을 계속 확인합니다.
    }
  }
  return null;
}

const METRICS_SUBDIR = "metrics";
const STAGE_ORDER = ["normalize", "detect", "correlate", "triage", "db", "investigation", "respond"];

// results/metrics/*.jsonl(파이프라인이 append)을 읽어 운영 상태 패널용으로 집계한다.
// 메트릭 폴더가 없거나 비면 null(= 미연결). 반쯤 쓰인 줄은 무시한다.
async function readOperations() {
  const dir = path.join(inputDir, METRICS_SUBDIR);
  let names;
  try {
    names = (await readdir(dir)).filter((name) => name.endsWith(".jsonl"));
  } catch {
    return null;
  }
  const rows = [];
  for (const name of names) {
    let text;
    try {
      text = await readFile(path.join(dir, name), "utf8");
    } catch {
      continue;
    }
    for (const line of text.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      try {
        rows.push(JSON.parse(trimmed));
      } catch {
        // 아직 완전히 기록되지 않은 줄 — 다음 틱에 다시 읽힌다.
      }
    }
  }
  if (!rows.length) return null;

  const byStage = new Map();
  for (const row of rows) {
    if (typeof row.duration_ms !== "number") continue;
    const acc = byStage.get(row.stage) ?? { stage: row.stage, total: 0, count: 0 };
    acc.total += row.duration_ms;
    acc.count += 1;
    byStage.set(row.stage, acc);
  }
  const stageDurations = [...byStage.values()]
    .map((acc) => ({ stage: acc.stage, avgMs: Math.round(acc.total / acc.count), count: acc.count }))
    .sort((a, b) => STAGE_ORDER.indexOf(a.stage) - STAGE_ORDER.indexOf(b.stage));

  const tokenTimeline = rows
    .filter((row) => typeof row.input_tokens === "number")
    .sort((a, b) => String(a.started_at).localeCompare(String(b.started_at)))
    .map((row) => ({
      startedAt: row.started_at,
      stage: row.stage,
      model: row.model ?? null,
      inputTokens: row.input_tokens ?? 0,
      outputTokens: row.output_tokens ?? 0,
      cacheReadTokens: row.cache_read_tokens ?? 0,
    }));

  const llmTotals = tokenTimeline.reduce((total, row) => ({
    inputTokens: total.inputTokens + row.inputTokens,
    outputTokens: total.outputTokens + row.outputTokens,
    cacheReadTokens: total.cacheReadTokens + row.cacheReadTokens,
    calls: total.calls + 1,
  }), { inputTokens: 0, outputTokens: 0, cacheReadTokens: 0, calls: 0 });

  return { stageDurations, tokenTimeline, llmTotals };
}

export async function syncResults({ writeModuleSnapshot = true } = {}) {
  let files;
  let responseFiles;
  try {
    [files, responseFiles] = await Promise.all([listResultFiles(), listResponseFiles()]);
  } catch {
    console.log(`[sync-results] 입력 디렉터리가 없어 기존 생성 데이터를 유지합니다: ${inputDir}`);
    try {
      const existingSnapshot = await readFile(outputPath, "utf8");
      JSON.parse(existingSnapshot);
      await mkdir(publicOutputDir, { recursive: true });
      await writeJsonIfChanged(publicOutputPath, existingSnapshot);
      console.log("[sync-results] 기존 정상 스냅샷을 브라우저용 데이터로 복사했습니다.");
    } catch {
      console.warn("[sync-results] 브라우저에 제공할 기존 정상 스냅샷도 없습니다.");
    }
    return null;
  }

  let incidents = [];
  const invalidFiles = [];
  for (const file of files) {
    try {
      const raw = JSON.parse(await readFile(path.join(inputDir, file), "utf8"));
      if (isMappingOnly(raw)) continue;
      const results = Array.isArray(raw.results) ? raw.results : raw.incident_id ? [raw] : [];
      for (const result of results) incidents.push(toIncident(result, file));
    } catch (error) {
      invalidFiles.push(file);
      console.warn(`[sync-results] 아직 읽을 수 없는 파일을 감지했습니다: ${file} (${error.message})`);
    }
  }

  const responsesByStem = new Map();
  const responsesByIdentity = new Map();
  for (const file of responseFiles) {
    try {
      const raw = JSON.parse(await readFile(path.join(inputDir, file), "utf8"));
      const response = toResponse(raw, file);
      if (!response) continue;
      responsesByStem.set(responseStem(file), response);
      const identity = `${cleanText(raw.incident_id, "")}::${cleanText(raw.investigation_id, "")}`;
      const matches = responsesByIdentity.get(identity) ?? [];
      matches.push(response);
      responsesByIdentity.set(identity, matches);
    } catch (error) {
      invalidFiles.push(file);
      console.warn(`[sync-results] 아직 읽을 수 없는 파일을 감지했습니다: ${file} (${error.message})`);
    }
  }

  // 생산 프로세스가 JSON을 쓰는 도중의 중간 상태를 대시보드에 배포하지 않습니다.
  // 감시 프로세스가 잠시 뒤 다시 시도하므로 기존의 정상 스냅샷은 그대로 유지됩니다.
  if (invalidFiles.length > 0) {
    throw new Error(`완전히 기록되지 않은 JSON ${invalidFiles.length}개가 있어 동기화를 보류했습니다.`);
  }

  for (const incident of incidents) {
    const exact = responsesByStem.get(responseStem(incident.sourceFile));
    const identity = `${incident.incidentId}::${incident.investigationId}`;
    const identityMatches = responsesByIdentity.get(identity) ?? [];
    // 동일 사건의 재출력(__2 등)은 파일 stem이 같은 대응 산출물을 최우선으로 연결합니다.
    incident.response = exact ?? (identityMatches.length === 1 ? identityMatches[0] : null);
  }

  incidents = latestPerIncident(incidents);
  incidents.sort((a, b) => String(b.timestamp).localeCompare(String(a.timestamp)));
  const pipeline = buildPipeline(await loadDetections(), incidents);
  if (pipeline.error) console.warn(`[sync-results] ${pipeline.error}`);
  const operations = await readOperations();
  const source = path.relative(defaultInputDir, inputDir) === ""
    ? "results/*.json"
    : "SSOC_RESULTS_DIR/*.json";
  const existingSnapshot = await readMatchingSnapshot(
    [publicOutputPath, outputPath],
    source,
    incidents,
    pipeline,
    operations,
  );
  const snapshot = existingSnapshot ?? { generatedAt: new Date().toISOString(), source, incidents, pipeline, operations };
  const contents = `${JSON.stringify(snapshot, null, 2)}\n`;

  await Promise.all([
    mkdir(outputDir, { recursive: true }),
    mkdir(publicOutputDir, { recursive: true }),
  ]);
  const targets = writeModuleSnapshot ? [outputPath, publicOutputPath] : [publicOutputPath];
  const changed = (await Promise.all(targets.map((target) => writeJsonIfChanged(target, contents)))).some(Boolean);
  const dbNote = pipeline.connected
    ? ` · DB 사건 ${pipeline.detections.length}건(이전 기록 ${pipeline.funnel.legacy}건 포함, 조사 결과와 연결 ${pipeline.linked}건)`
    : "";
  console.log(changed
    ? `[sync-results] ${incidents.length}건 저장${dbNote} · ${snapshot.generatedAt}`
    : `[sync-results] 변경 없음 · ${incidents.length}건${dbNote}`);
  return snapshot;
}

const invokedPath = process.argv[1] ? path.resolve(process.argv[1]) : "";
if (invokedPath === fileURLToPath(import.meta.url)) await syncResults();
