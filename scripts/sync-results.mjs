import { mkdir, readdir, readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";
import { loadEnvFile } from "node:process";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const projectDir = path.resolve(scriptDir, "..");
const resultsDirFromProcess = process.env.SSOC_RESULTS_DIR;

try {
  loadEnvFile(path.join(projectDir, ".env"));
} catch (error) {
  if (error?.code !== "ENOENT") throw error;
}

// 셸이나 배포 환경에서 직접 지정한 값이 로컬 .env 설정보다 우선합니다.
if (resultsDirFromProcess !== undefined) process.env.SSOC_RESULTS_DIR = resultsDirFromProcess;

const configuredResultsDir = process.env.SSOC_RESULTS_DIR?.trim();
const defaultInputDir = path.join(projectDir, "results");
export const inputDir = configuredResultsDir
  ? path.resolve(projectDir, configuredResultsDir)
  : defaultInputDir;
const outputDir = path.join(projectDir, "data");
const outputPath = path.join(outputDir, "incidents.generated.json");
const publicOutputDir = path.join(projectDir, "public", "data");
const publicOutputPath = path.join(publicOutputDir, "incidents.generated.json");

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

async function readMatchingSnapshot(paths, source, incidents) {
  const expected = JSON.stringify({ source, incidents });
  for (const candidatePath of paths) {
    try {
      const candidate = JSON.parse(await readFile(candidatePath, "utf8"));
      if (
        typeof candidate.generatedAt === "string"
        && JSON.stringify({ source: candidate.source, incidents: candidate.incidents }) === expected
      ) return candidate;
    } catch {
      // 다른 후보 스냅샷을 계속 확인합니다.
    }
  }
  return null;
}

export async function syncResults({ writeModuleSnapshot = true } = {}) {
  let files;
  try {
    files = (await readdir(inputDir)).filter((name) => name.endsWith(".json")).sort();
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

  const incidents = [];
  const invalidFiles = [];
  for (const file of files) {
    try {
      const raw = JSON.parse(await readFile(path.join(inputDir, file), "utf8"));
      const results = Array.isArray(raw.results) ? raw.results : raw.incident_id ? [raw] : [];
      for (const result of results) incidents.push(toIncident(result, file));
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

  incidents.sort((a, b) => String(b.timestamp).localeCompare(String(a.timestamp)));
  const source = path.relative(defaultInputDir, inputDir) === ""
    ? "results/*.json"
    : "SSOC_RESULTS_DIR/*.json";
  const existingSnapshot = await readMatchingSnapshot(
    [publicOutputPath, outputPath],
    source,
    incidents,
  );
  const snapshot = existingSnapshot ?? { generatedAt: new Date().toISOString(), source, incidents };
  const contents = `${JSON.stringify(snapshot, null, 2)}\n`;

  await Promise.all([
    mkdir(outputDir, { recursive: true }),
    mkdir(publicOutputDir, { recursive: true }),
  ]);
  const targets = writeModuleSnapshot ? [outputPath, publicOutputPath] : [publicOutputPath];
  const changed = (await Promise.all(targets.map((target) => writeJsonIfChanged(target, contents)))).some(Boolean);
  console.log(changed
    ? `[sync-results] ${incidents.length}건 저장 · ${snapshot.generatedAt}`
    : `[sync-results] 변경 없음 · ${incidents.length}건`);
  return snapshot;
}

const invokedPath = process.argv[1] ? path.resolve(process.argv[1]) : "";
if (invokedPath === fileURLToPath(import.meta.url)) await syncResults();
