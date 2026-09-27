import { mkdir, readdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const projectDir = path.resolve(scriptDir, "..");
const inputDir = process.env.SSOC_RESULTS_DIR
  ? path.resolve(process.env.SSOC_RESULTS_DIR)
  : path.resolve(projectDir, "..", "000", "results");
const outputDir = path.join(projectDir, "data");
const outputPath = path.join(outputDir, "incidents.generated.json");

const cleanText = (value, fallback = "-") =>
  typeof value === "string" && value.trim() ? value.trim() : fallback;

const toIncident = (result, sourceFile) => {
  const verdict = result.final_verdict ?? {};
  const seed = result.initial_seed ?? {};
  const stats = result.statistics ?? {};
  const provenance = result.provenance ?? {};

  return {
    sourceFile,
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
  };
};

async function main() {
  let files;
  try {
    files = (await readdir(inputDir)).filter((name) => name.endsWith(".json")).sort();
  } catch {
    console.log(`[sync-results] 입력 디렉터리가 없어 기존 생성 데이터를 유지합니다: ${inputDir}`);
    return;
  }

  const incidents = [];
  for (const file of files) {
    const raw = JSON.parse(await readFile(path.join(inputDir, file), "utf8"));
    const results = Array.isArray(raw.results) ? raw.results : raw.incident_id ? [raw] : [];
    for (const result of results) incidents.push(toIncident(result, file));
  }

  incidents.sort((a, b) => String(b.timestamp).localeCompare(String(a.timestamp)));
  await mkdir(outputDir, { recursive: true });
  await writeFile(
    outputPath,
    `${JSON.stringify({ generatedAt: new Date().toISOString(), source: "000/results/*.json", incidents }, null, 2)}\n`,
    "utf8",
  );
  console.log(`[sync-results] ${incidents.length}건 저장: ${outputPath}`);
}

await main();
