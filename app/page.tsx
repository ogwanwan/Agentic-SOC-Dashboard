"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  BarChart3,
  Bot,
  BrainCircuit,
  createLucideIcon,
  ChevronRight,
  CircleDashed,
  Clock3,
  Database,
  FileCode2,
  Fingerprint,
  GitBranch,
  Layers3,
  LayoutDashboard,
  ListTree,
  Network,
  Radio,
  RefreshCw,
  RotateCcw,
  Search,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  TerminalSquare,
  TimerReset,
  Waypoints,
  WifiOff,
  Wrench,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Bar, BarChart, CartesianGrid, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import resultData from "@/data/incidents.generated.json";
// 대응 조치 탭은 완성 전까지 임시 비활성화합니다. 관련 구현은 보존합니다.
// import { ResponseCenter } from "@/components/response-center";
import type { ResponseData } from "@/lib/response";

const ChartDonut = createLucideIcon("chart-donut", [
  // 기본 Lucide 원형 아이콘과 동일한 바깥 여백과 도형 범위를 사용합니다.
  ["circle", { cx: 12, cy: 12, r: 10, key: "outer" }],
  ["circle", { cx: 12, cy: 12, r: 6, key: "inner" }],
  ["path", { d: "M12 2v4M22 12h-4M4.93 19.07l2.83-2.83", key: "segments" }],
]);

type Incident = (typeof resultData.incidents)[number];
type DashboardData = typeof resultData;
type View = "overview" | "incidents" | "operations" | "pipeline";
// 대응 조치 탭 재활성화 시 View에 "responses"를 추가합니다.
type Timezone = "UTC" | "KST";
type SyncStatus = "connecting" | "live" | "retrying";
type IncidentVerdictFilter = "ALL" | "THREAT_CONFIRMED" | "FALSE_POSITIVE" | "INCONCLUSIVE";
type IncidentSeverityFilter = "ALL" | "URGENT" | "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";
type IncidentFilterPreset = {
  revision: number;
  verdict: IncidentVerdictFilter;
  severity: IncidentSeverityFilter;
};
type IncidentViewPreset = {
  revision: number;
  tab: "results" | "detections";
  detectionState: string;
};

// ATT&CK 매핑 결과(scripts/sync-results.mjs toAttackMapping). 매핑 전 결과에는 없으므로
// 생성 JSON에서 타입을 추론하지 않고 직접 정의합니다.
type EvidenceMapping = { state: string; techniques: string[]; reasons: string[] } | null;
type AttackMapping = {
  status: string;
  method: string;
  attackVersion: string;
  retrievalVersion: string;
  techniques: { id: string; name: string; tactic: string; parent: string; evidenceIds: string[]; reasons: { evidenceIds: string[]; reason: string }[] }[];
  killChain: { step: number; tactic: string; techniqueId: string; techniqueName: string; time: string; evidenceIds: string[] }[];
  trace: { evidenceId: string; candidates: string[]; selected: string[] }[];
  exclusions: { evidenceId: string; reasons: string[] }[];
  unmatched: string[];
  rejected: { evidenceId: string; value: string; code: string }[];
  errors: string[];
};

function attackMappingOf(incident: Incident): AttackMapping | null {
  return (incident as Incident & { attackMapping?: AttackMapping | null }).attackMapping ?? null;
}

function responseOf(incident: Incident): ResponseData | null {
  return (incident as Incident & { response?: ResponseData | null }).response ?? null;
}

function evidenceMappingOf(item: object): EvidenceMapping {
  return (item as { mapping?: EvidenceMapping }).mapping ?? null;
}

const mappingStatusMeta: Record<string, { label: string; style: string }> = {
  mapped: { label: "매핑 완료", style: "border-cyan-400/25 bg-cyan-400/8 text-cyan-200" },
  partial: { label: "부분 매핑 · 원본 미확인 증거 제외", style: "border-amber-400/25 bg-amber-400/8 text-amber-300" },
  no_techniques_matched: { label: "일치하는 기법 없음", style: "border-slate-400/20 bg-slate-400/8 text-slate-300" },
  not_applicable: { label: "오탐 판정 · 매핑 안 함", style: "border-emerald-400/25 bg-emerald-400/8 text-emerald-300" },
  deferred: { label: "판단 보류 · 매핑 안 함", style: "border-slate-400/20 bg-slate-400/8 text-slate-300" },
  error: { label: "매핑 오류", style: "border-rose-400/25 bg-rose-400/8 text-rose-300" },
};

const evidenceMappingMeta: Record<string, { label: string; style: string }> = {
  mapped: { label: "매핑", style: "border-cyan-400/25 text-cyan-200" },
  excluded: { label: "매핑 제외", style: "border-slate-500/30 text-slate-400" },
  unmatched: { label: "일치 기법 없음", style: "border-amber-400/25 text-amber-300" },
  context: { label: "매핑 참고 문맥", style: "border-slate-500/30 text-slate-400" },
};

const exclusionReasonLabel: Record<string, string> = {
  NO_RAW_REFS: "원본 줄 없음",
  PROVENANCE_ISSUE: "원본 검증 문제",
  EMPTY_RESULT: "0건 조회 증거",
  AMBIGUOUS_RAW_REF: "모호한 참조",
  UNOBSERVED_RAW_REF: "관측되지 않은 참조",
  CONTRADICTING: "반박 증거",
};

// 1차 탐지 DB(soc.db) 정보(scripts/sync-results.mjs buildPipeline). SSOC_DB_PATH 를 지정했을 때만 있습니다.
type TriageParts = { severity: number; layers: number; joinTypes: number; seedCount: number };
type Detection = {
  incidentKey: string;
  incidentId: string;
  entityType: string;
  entityValue: string;
  window: string[];
  layers: string[];
  memberCount: number;
  priority: string;
  score: number;
  parts: TriageParts | null;
  route: string;
  llmInvestigate: boolean | null;
  llmReason: string;
  state: string;
  hasUpdate: boolean;
  firstDetected: string;
  updatedAt: string;
  rules: string[];
  ruleCount: number;
  investigated: boolean;
  resultKey: string;
};
type PipelineData = {
  enabled: boolean;
  connected: boolean;
  error: string;
  linked: number;
  funnel: {
    detected: number;
    legacy: number;
    byPriority: Record<string, number>;
    targeted: number;
    llmFiltered: number;
    queued: number;
    investigating: number;
    resultUnmarked: number;
    investigated: number;
    threat: number;
    falsePositive: number;
    inconclusive: number;
    mapped: number;
  };
  detections: Detection[];
};
type IncidentTriage = {
  priority: string;
  score: number;
  parts: TriageParts | null;
  llmInvestigate: boolean | null;
  llmReason: string;
  firstDetected: string;
  updatedAt: string;
  rules: string[];
  layers: string[];
} | null;

function pipelineOf(data: DashboardData): PipelineData | null {
  return (data as DashboardData & { pipeline?: PipelineData }).pipeline ?? null;
}

function triageOf(incident: Incident): IncidentTriage {
  return (incident as Incident & { triage?: IncidentTriage }).triage ?? null;
}

// 트리아지 점수 구성 — 파이프라인 triage.py 의 네 요소
const triagePartMeta: { key: keyof TriageParts; label: string; color: string }[] = [
  { key: "severity", label: "룰 심각도", color: "bg-rose-400" },
  { key: "layers", label: "계층 수", color: "bg-orange-400" },
  { key: "joinTypes", label: "연결 종류", color: "bg-teal-400" },
  { key: "seedCount", label: "탐지 수", color: "bg-violet-400" },
];

const detectionStateMeta: Record<string, { label: string; style: string }> = {
  queued: { label: "조사 대기", style: "border-amber-400/25 bg-amber-400/8 text-amber-300" },
  investigating: { label: "조사 중", style: "border-cyan-400/25 bg-cyan-400/8 text-cyan-200" },
  done: { label: "조사 완료", style: "border-emerald-400/25 bg-emerald-400/8 text-emerald-300" },
  result_unmarked: { label: "조사 완료 · DB 미반영", style: "border-emerald-400/20 bg-transparent text-emerald-300/80" },
  llm_filtered: { label: "Haiku 오탐 제외", style: "border-slate-400/20 bg-slate-400/8 text-slate-300" },
  not_targeted: { label: "조사 대상 아님", style: "border-slate-500/20 bg-transparent text-slate-400" },
  legacy: { label: "이전 기록", style: "border-dashed border-slate-500/30 bg-transparent text-slate-500" },
};

const priorityStyle: Record<string, string> = {
  P1: "text-rose-300",
  P2: "text-orange-300",
  P3: "text-slate-300",
  P4: "text-slate-500",
};

function attackUrl(techniqueId: string) {
  return /^T\d{4}(\.\d{3})?$/.test(techniqueId)
    ? `https://attack.mitre.org/techniques/${techniqueId.replace(".", "/")}/`
    : null;
}

const navigation = [
  { id: "overview" as View, label: "상황 개요", description: "우선순위와 위협 추이", icon: LayoutDashboard },
  { id: "incidents" as View, label: "사건", description: "조사 결과와 근거", icon: ListTree },
  // { id: "responses" as View, label: "대응 조치", description: "권고·적용·검증", icon: ShieldCheck },
  { id: "pipeline" as View, label: "파이프라인", description: "분석 단계와 연결 상태", icon: GitBranch },
  { id: "operations" as View, label: "운영 상태", description: "성능과 데이터 품질", icon: Activity },
];

const severityOrder: Record<string, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  UNKNOWN: 4,
};

const severityStyle: Record<string, string> = {
  CRITICAL: "border-rose-400/30 bg-rose-400/10 text-rose-300",
  HIGH: "border-orange-400/30 bg-orange-400/10 text-orange-300",
  MEDIUM: "border-amber-400/30 bg-amber-400/10 text-amber-300",
  LOW: "border-blue-400/30 bg-blue-400/10 text-blue-300",
  UNKNOWN: "border-slate-400/20 bg-slate-400/10 text-slate-300",
};

const severityAccent: Record<string, string> = {
  CRITICAL: "bg-rose-400",
  HIGH: "bg-orange-400",
  MEDIUM: "bg-amber-400",
  LOW: "bg-blue-400",
  UNKNOWN: "bg-slate-400",
};

const verdictMeta: Record<string, { label: string; color: string; icon: typeof Shield }> = {
  THREAT_CONFIRMED: { label: "위협 확인", color: "text-rose-300", icon: ShieldAlert },
  FALSE_POSITIVE: { label: "비위협 판정", color: "text-emerald-300", icon: ShieldCheck },
  INCONCLUSIVE: { label: "결론 불충분", color: "text-amber-300", icon: AlertTriangle },
};

function formatDate(value: string, timezone: Timezone, withDate = true): string {
  if (!value) return "-";
  // 조사 증거의 시간 범위 표기("시작~끝")는 양쪽을 각각 변환합니다.
  if (value.includes("~")) {
    const [start, end] = value.split("~", 2);
    return `${formatDate(start.trim(), timezone, withDate)} ~ ${formatDate(end.trim(), timezone, false)}`;
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat("ko-KR", {
    month: withDate ? "2-digit" : undefined,
    day: withDate ? "2-digit" : undefined,
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
    timeZone: timezone === "KST" ? "Asia/Seoul" : "UTC",
  }).format(date);
}

function formatSyncTime(value: string, timezone: Timezone) {
  if (!value) return "아직 동기화되지 않음";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat("ko-KR", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
    timeZone: timezone === "KST" ? "Asia/Seoul" : "UTC",
  }).format(date);
}

function isDashboardData(value: unknown): value is DashboardData {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Partial<DashboardData>;
  return typeof candidate.generatedAt === "string" && Array.isArray(candidate.incidents);
}

function percent(value: number) {
  return `${Math.round(Number(value || 0) * 100)}%`;
}

function VerdictLabel({ verdict }: { verdict: string }) {
  const meta = verdictMeta[verdict] ?? verdictMeta.INCONCLUSIVE;
  const Icon = meta.icon;
  return (
    <span className={`inline-flex items-center gap-1.5 text-sm font-medium ${meta.color}`}>
      <Icon className="size-4" />
      {meta.label}
    </span>
  );
}

function SeverityBadge({ severity }: { severity: string }) {
  return (
    <Badge variant="outline" className={`font-mono text-[0.7rem] ${severityStyle[severity] ?? severityStyle.UNKNOWN}`}>
      {severity}
    </Badge>
  );
}

function ProvenanceBadge({ status }: { status: string }) {
  const style =
    status === "passed"
      ? "border-emerald-400/25 bg-emerald-400/8 text-emerald-300"
      : status === "incomplete"
        ? "border-amber-400/25 bg-amber-400/8 text-amber-300"
        : "border-slate-400/20 bg-slate-400/8 text-slate-300";
  const label = status === "passed" ? "근거 검증" : status === "incomplete" ? "근거 불완전" : "근거 없음";
  return <Badge variant="outline" className={style}>{label}</Badge>;
}

function PanelTitle({
  icon: Icon,
  title,
  description,
  trailing,
}: {
  icon: typeof Shield;
  title: string;
  description?: string;
  trailing?: React.ReactNode;
}) {
  return (
    <div className="flex items-start justify-between gap-4">
      <div className="flex items-start gap-3">
        <div className="grid size-9 shrink-0 place-items-center rounded-lg border border-cyan-400/20 bg-cyan-400/8 text-cyan-300">
          <Icon size={16} strokeWidth={2} className="size-4 shrink-0" />
        </div>
        <div>
          <h2 className="font-semibold tracking-tight">{title}</h2>
          {description && <p className="mt-1 text-sm text-muted-foreground">{description}</p>}
        </div>
      </div>
      {trailing}
    </div>
  );
}

function EmptyMetric({ label }: { label: string }) {
  return (
    <div className="grid min-h-48 place-items-center rounded-xl border border-dashed border-white/10 bg-black/10 px-6 text-center">
      <div>
        <CircleDashed className="mx-auto size-7 text-slate-600" />
        <p className="mt-3 text-sm font-medium text-slate-300">{label}</p>
        <p className="mt-1 text-sm leading-6 text-muted-foreground">메트릭 입력이 연결되면 이 영역이 자동으로 활성화됩니다.</p>
      </div>
    </div>
  );
}

function TriageScoreBar({ score, parts, wide = false }: { score: number; parts: TriageParts | null; wide?: boolean }) {
  if (!parts) return <span className="text-xs text-slate-500" title="state.json 에서 옮겨 온 예전 기록이라 트리아지 정보가 없습니다. 새 활동이 생기면 채워집니다.">트리아지 정보 없음</span>;
  return (
    <span className="flex items-center gap-2" title={triagePartMeta.map((part) => `${part.label} ${parts[part.key]}점`).join(" · ")}>
      <span className="w-7 font-mono text-sm font-semibold text-slate-100">{score}</span>
      <span className={`flex h-1.5 overflow-hidden rounded-full bg-white/6 ${wide ? "w-48" : "w-24"}`}>
        {triagePartMeta.map((part) => parts[part.key] > 0 && <span key={part.key} className={part.color} style={{ width: `${Math.min(100, parts[part.key])}%` }} />)}
      </span>
    </span>
  );
}

function TriageLegend({ parts }: { parts?: TriageParts | null }) {
  return (
    <span className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
      {triagePartMeta.map((part) => <span key={part.key} className="flex items-center gap-1.5"><i className={`size-2 rounded-full ${part.color}`} />{part.label}{parts ? ` ${parts[part.key]}점` : ""}</span>)}
    </span>
  );
}

type OverviewCounts = {
  all: number;
  threat: number;
  benign: number;
  urgent: number;
  inconclusive: number;
  verified: number;
  responses: number;
};

function PipelineFunnel({
  pipeline,
  counts,
  onOpenFilteredIncidents,
  onOpenDetectionQueue,
}: {
  pipeline: PipelineData | null;
  counts: OverviewCounts;
  onOpenFilteredIncidents: (filter: Pick<IncidentFilterPreset, "verdict" | "severity">) => void;
  onOpenDetectionQueue: () => void;
}) {
  if (!pipeline?.enabled) return null;
  if (!pipeline.connected) {
    return <section className="rounded-xl border border-amber-400/20 bg-amber-400/5 p-4 text-sm text-amber-100/80"><span className="font-semibold text-amber-300">1차 탐지 DB 미연결</span> · {pipeline.error || "SSOC_DB_PATH 경로를 확인하세요."} 조사 결과는 그대로 표시됩니다.</section>;
  }
  const f = pipeline.funnel;
  const targetConversionRate = f.detected > 0 ? (f.targeted / f.detected) * 100 : 0;
  const completionRate = f.targeted > 0 ? (f.investigated / f.targeted) * 100 : 0;
  const isStalled = f.queued > 0 && f.investigating === 0;
  const investigationState = isStalled ? "처리 정체" : f.investigating > 0 ? "처리 중" : "대기 없음";
  const InvestigationStateIcon = isStalled ? AlertTriangle : Activity;
  const outcomeTiles = [
    { label: "위협 확인", value: counts.threat, icon: ShieldAlert, color: "text-rose-300", style: "border-rose-400/20 bg-rose-400/[0.05] hover:border-rose-400/35", filter: { verdict: "THREAT_CONFIRMED", severity: "ALL" } },
    { label: "비위협", value: counts.benign, icon: ShieldCheck, color: "text-[#55d58b]", style: "border-[#55d58b]/20 bg-[#55d58b]/[0.05] hover:border-[#55d58b]/35", filter: { verdict: "FALSE_POSITIVE", severity: "ALL" } },
    { label: "추가 조사", value: counts.inconclusive, icon: CircleDashed, color: "text-amber-300", style: "border-amber-400/20 bg-amber-400/[0.05] hover:border-amber-400/35", filter: { verdict: "INCONCLUSIVE", severity: "ALL" } },
  ] as const;

  return (
    <section className="signal-card p-5 sm:p-6">
      <PanelTitle
        icon={Waypoints}
        title="탐지에서 판정까지"
        description="1차 탐지 DB의 사건이 트리아지와 조사 에이전트를 거쳐 최종 판정되고, ATT&CK 매핑과 대응 권고로 이어지는 전체 흐름입니다."
      />

      <div className="mt-6 grid gap-3 sm:grid-cols-2 xl:grid-cols-[minmax(0,0.85fr)_minmax(0,0.9fr)_minmax(0,1.4fr)_minmax(0,0.95fr)]">
        <article className="relative flex min-h-56 flex-col rounded-xl border border-white/8 bg-white/[0.025] p-4">
          <div className="flex items-center gap-3 pr-20">
            <span className="grid size-10 place-items-center rounded-full border border-slate-100/35 bg-slate-100/[0.04] text-slate-100">
              <Search aria-hidden="true" className="size-5" />
            </span>
            <h3 className="text-sm font-semibold text-slate-100">탐지 사건</h3>
          </div>
          <strong className="absolute right-4 top-4 font-mono text-4xl font-semibold tracking-tight text-slate-100">{f.detected}</strong>
          <div className="mt-4 min-w-0">
            <p className="text-[0.68rem] font-semibold tracking-[0.12em] text-slate-400">우선순위</p>
            <div className="mt-1 space-y-0.5 font-mono text-xs text-slate-300">
              {(["P1", "P2", "P3", "P4"] as const).map((priority) => (
                <div key={priority} className="flex items-center justify-between border-b border-white/[0.05] py-0.5 last:border-b-0">
                  <span>{priority}</span>
                  <strong className="font-semibold text-slate-100">{f.byPriority[priority] ?? 0}</strong>
                </div>
              ))}
            </div>
          </div>
          {f.legacy > 0 && <p className="mt-1.5 text-xs text-slate-500">이전 기록 {f.legacy}건 제외</p>}
          <ArrowRight aria-hidden="true" className="absolute -right-[0.7rem] top-1/2 z-10 hidden size-4 -translate-y-1/2 text-slate-500 xl:block" />
        </article>

        <article className="relative flex min-h-56 flex-col rounded-xl border border-white/8 bg-white/[0.025] p-4">
          <div className="flex items-center gap-3 pr-20">
            <span className="grid size-10 place-items-center rounded-full border border-orange-400/25 bg-orange-400/[0.06] text-orange-300">
              <Bot aria-hidden="true" className="size-5" />
            </span>
            <h3 className="text-sm font-semibold text-slate-100">조사 대상</h3>
          </div>
          <strong className="absolute right-4 top-4 font-mono text-4xl font-semibold tracking-tight text-orange-300">{f.targeted}</strong>
          <div className="mt-3">
            <div className="flex items-center justify-between text-muted-foreground">
              <span className="text-[0.68rem] font-semibold tracking-[0.12em] text-slate-400">전환율</span>
              <strong className="font-mono text-xs font-semibold text-orange-200">{targetConversionRate.toFixed(1)}%</strong>
            </div>
            <button type="button" onClick={onOpenDetectionQueue} className="mt-2 flex h-8 w-full items-center justify-between gap-2 rounded-lg border border-orange-400/20 bg-orange-400/[0.05] px-2.5 text-xs text-orange-200 transition hover:border-orange-400/40 hover:bg-orange-400/[0.09]" aria-label="탐지 대기열의 조사 대기 사건 확인">
              <span className="flex min-w-0 items-center gap-1.5"><InvestigationStateIcon aria-hidden="true" className="size-3.5 shrink-0" /><span className="truncate">대기 {f.queued} · 조사 중 {f.investigating}</span></span>
              <span className="shrink-0 font-semibold">{investigationState}</span>
            </button>
            <div className="mt-2.5 flex items-center justify-between text-xs text-muted-foreground">
              <span>조사 완료 {f.investigated}/{f.targeted}</span>
              <strong className="font-mono text-orange-200">{completionRate.toFixed(1)}%</strong>
            </div>
            <div className="mt-1 h-1.5 overflow-hidden rounded-full border border-orange-400/15 bg-black/25" role="progressbar" aria-label="조사 완료율" aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.min(100, completionRate)}>
              <div className="h-full rounded-full bg-orange-300 transition-[width]" style={{ width: `${Math.min(100, completionRate)}%` }} />
            </div>
            <p className="mt-2 text-xs text-slate-500">Sonnet 오탐 제외 {f.llmFiltered}건</p>
          </div>
          <ArrowRight aria-hidden="true" className="absolute -right-[0.7rem] top-1/2 z-10 hidden size-4 -translate-y-1/2 text-slate-500 xl:block" />
        </article>

        <article className="relative min-h-56 rounded-xl border border-white/8 bg-white/[0.025] p-4">
          <div className="flex items-center gap-3 pr-16">
            <span className="grid size-10 place-items-center rounded-full border border-cyan-400/25 bg-cyan-400/[0.06] text-cyan-300">
              <Activity aria-hidden="true" className="size-5" />
            </span>
            <h3 className="text-sm font-semibold text-slate-100">조사 완료</h3>
          </div>
          <button type="button" onClick={() => onOpenFilteredIncidents({ verdict: "ALL", severity: "ALL" })} className="absolute right-4 top-4 font-mono text-4xl font-semibold tracking-tight text-cyan-300 transition hover:text-cyan-200" aria-label={`전체 조사 ${counts.all}건 사건 목록 보기`}>{counts.all}</button>
          <div className="mt-4 grid grid-cols-3 gap-1.5">
            {outcomeTiles.map((item) => {
              const Icon = item.icon;
              return (
                <button key={item.label} type="button" onClick={() => onOpenFilteredIncidents(item.filter)} className={`min-w-0 rounded-lg border p-2.5 text-left transition ${item.style}`} aria-label={`${item.label} ${item.value}건 사건 목록 보기`}>
                  <span className={`flex items-center gap-1 text-[0.68rem] font-medium ${item.color}`}><Icon aria-hidden="true" className="size-3.5 shrink-0" /><span className="whitespace-nowrap">{item.label}</span></span>
                  <strong className={`mt-2 block font-mono text-2xl font-semibold ${item.color}`}>{item.value}</strong>
                </button>
              );
            })}
          </div>
          <ArrowRight aria-hidden="true" className="absolute -right-[0.7rem] top-1/2 z-10 hidden size-4 -translate-y-1/2 text-slate-500 xl:block" />
        </article>

        <article className="relative min-h-56 rounded-xl border border-white/8 bg-white/[0.025] p-4">
          <div className="flex items-center gap-3 pr-16">
            <span className="grid size-10 place-items-center rounded-full border border-violet-400/25 bg-violet-400/[0.06] text-violet-300">
              <ShieldCheck aria-hidden="true" className="size-5" />
            </span>
            <h3 className="text-sm font-semibold text-slate-100">최종 판정</h3>
          </div>
          <strong className="absolute right-4 top-4 font-mono text-4xl font-semibold tracking-tight text-violet-300">{counts.all}</strong>
          <div className="mt-4 grid grid-cols-2 gap-1.5">
            <div className="min-w-0 rounded-lg border border-violet-400/20 bg-violet-400/[0.04] p-2.5 text-left">
              <span className="flex items-center gap-1 text-[0.68rem] font-medium text-violet-300"><Network aria-hidden="true" className="size-3.5 shrink-0" /><span className="whitespace-nowrap">ATT&amp;CK 매핑</span></span>
              <strong className="mt-2 block font-mono text-2xl font-semibold text-violet-300">{f.mapped}</strong>
            </div>
            <div className="min-w-0 rounded-lg border border-violet-400/20 bg-violet-400/[0.04] p-2.5 text-left">
              <span className="flex items-center gap-1 text-[0.68rem] font-medium text-violet-300"><Wrench aria-hidden="true" className="size-3.5 shrink-0" /><span className="whitespace-nowrap">대응 권고 생성</span></span>
              <strong className="mt-2 block font-mono text-2xl font-semibold text-violet-300">{counts.responses}</strong>
            </div>
          </div>
        </article>
      </div>

      {pipeline.linked < f.investigated && <p className="mt-4 text-xs leading-5 text-amber-300/80">조사 결과 {f.investigated}건 중 {f.investigated - pipeline.linked}건은 DB에서 같은 사건을 찾지 못했습니다. 결과 폴더(SSOC_RESULTS_DIR)와 DB(SSOC_DB_PATH)가 같은 파이프라인 실행의 것인지 확인하세요.</p>}
    </section>
  );
}

function Overview({ incidents, pipeline, onOpenIncident, onOpenFilteredIncidents, onOpenDetectionQueue, timezone }: { incidents: Incident[]; pipeline: PipelineData | null; onOpenIncident: (item: Incident) => void; onOpenFilteredIncidents: (filter: Pick<IncidentFilterPreset, "verdict" | "severity">) => void; onOpenDetectionQueue: () => void; timezone: Timezone }) {
  const counts = useMemo(() => ({
    all: incidents.length,
    threat: incidents.filter((item) => item.verdict === "THREAT_CONFIRMED").length,
    benign: incidents.filter((item) => item.verdict === "FALSE_POSITIVE").length,
    urgent: incidents.filter((item) => ["CRITICAL", "HIGH"].includes(item.severity)).length,
    inconclusive: incidents.filter((item) => item.verdict === "INCONCLUSIVE").length,
    verified: incidents.filter((item) => item.provenance.status === "passed").length,
    responses: incidents.filter((item) => Boolean(responseOf(item))).length,
  }), [incidents]);

  const timelineData = useMemo(() => {
    const buckets = new Map<string, { stamp: number; label: string; threat: number; benign: number; inconclusive: number }>();
    for (const incident of incidents) {
      const parsed = new Date(incident.triggerTime || incident.timestamp);
      if (Number.isNaN(parsed.getTime())) continue;
      const key = parsed.toISOString().slice(0, 13);
      const bucket = buckets.get(key) ?? {
        stamp: parsed.setMinutes(0, 0, 0),
        label: formatDate(parsed.toISOString(), timezone),
        threat: 0,
        benign: 0,
        inconclusive: 0,
      };
      if (incident.verdict === "THREAT_CONFIRMED") bucket.threat += 1;
      else if (incident.verdict === "FALSE_POSITIVE") bucket.benign += 1;
      else bucket.inconclusive += 1;
      buckets.set(key, bucket);
    }
    return [...buckets.values()].sort((a, b) => a.stamp - b.stamp);
  }, [incidents, timezone]);

  const severityData = useMemo(() => ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"].map((name) => ({
    name,
    value: incidents.filter((item) => item.severity === name).length,
  })).filter((item) => item.value > 0), [incidents]);
  const severityColors: Record<string, string> = { CRITICAL: "#ff6673", HIGH: "#ff9466", MEDIUM: "#f5c451", LOW: "#66aef7", UNKNOWN: "#82949d" };

  const attention = useMemo(() => [...incidents]
    .sort((a, b) => {
      const severityGap = (severityOrder[a.severity] ?? 9) - (severityOrder[b.severity] ?? 9);
      const provenanceGap = Number(b.provenance.status !== "passed") - Number(a.provenance.status !== "passed");
      return severityGap || provenanceGap || String(b.triggerTime).localeCompare(String(a.triggerTime));
    })
    .slice(0, 5), [incidents]);

  const rawReferenceCount = incidents.reduce((sum, item) => sum + item.provenance.rawRefCount, 0);
  const averageConfidence = incidents.length
    ? incidents.reduce((sum, item) => sum + item.investigationConfidence, 0) / incidents.length
    : 0;
  return (
    <div className="space-y-5">
      <PipelineFunnel pipeline={pipeline} counts={counts} onOpenFilteredIncidents={onOpenFilteredIncidents} onOpenDetectionQueue={onOpenDetectionQueue} />

      <section className="grid gap-5 xl:grid-cols-[minmax(0,1.35fr)_minmax(20rem,0.65fr)]">
        <article className="signal-card overflow-hidden">
          <div className="border-b border-white/7 p-5 sm:p-6">
            <PanelTitle icon={ShieldAlert} title="우선 확인 사건" description="심각도, 근거 상태, 탐지 시각을 함께 반영했습니다." />
          </div>
          <div className="divide-y divide-white/7 px-5 sm:px-6">
            {attention.map((incident) => (
              <button
                type="button"
                key={incident.investigationId}
                onClick={() => onOpenIncident(incident)}
                className="priority-incident group flex w-full items-center gap-4 py-4 text-left"
              >
                <span className={`h-12 w-1 shrink-0 rounded-full ${severityAccent[incident.severity] ?? severityAccent.UNKNOWN}`} />
                <span className="min-w-0 flex-1">
                  <span className="flex flex-wrap items-center gap-2">
                    <SeverityBadge severity={incident.severity} />
                    <span className="font-mono text-xs text-muted-foreground">{incident.incidentId}</span>
                    {incident.provenance.status !== "passed" && <span className="text-xs text-amber-300">근거 확인 필요</span>}
                  </span>
                  <span className="mt-2 block truncate text-sm font-semibold text-slate-100">{incident.title}</span>
                  <span className="mt-1 flex flex-wrap gap-x-3 gap-y-1 text-xs text-muted-foreground">
                    <span>{incident.host}</span>
                    <span>{formatDate(incident.triggerTime, timezone)} {timezone}</span>
                  </span>
                </span>
                <ChevronRight aria-hidden="true" className="size-5 shrink-0 text-slate-500 transition group-hover:translate-x-1 group-hover:text-cyan-300" />
              </button>
            ))}
            {!attention.length && <div className="py-12 text-center text-sm text-muted-foreground">표시할 사건이 없습니다.</div>}
          </div>
        </article>

        <article className="signal-card p-5 sm:p-6">
          <PanelTitle icon={ChartDonut} title="심각도 분포" description="현재 연결된 최종 판정" />
          {severityData.length ? (
            <>
              <div className="mt-4 grid min-h-60 grid-cols-[minmax(0,1fr)_7.5rem] items-center gap-1">
                <div className="relative h-56 min-w-0">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart accessibilityLayer>
                      <Pie data={severityData} dataKey="value" nameKey="name" innerRadius={60} outerRadius={86} paddingAngle={3} cornerRadius={5} stroke="none" isAnimationActive={false}>
                        {severityData.map((item) => <Cell key={item.name} fill={severityColors[item.name]} />)}
                      </Pie>
                      <Tooltip formatter={(value, name) => [`${value}건`, name]} contentStyle={{ background: "#0c181e", border: "1px solid #26434d", borderRadius: 10, fontSize: 13 }} />
                    </PieChart>
                  </ResponsiveContainer>
                  <div className="pointer-events-none absolute inset-0 grid place-content-center text-center"><strong className="font-mono text-3xl">{incidents.length}</strong><span className="mt-1 text-sm text-muted-foreground">전체</span></div>
                </div>
                <div className="space-y-3">
                  {severityData.map((item) => <div key={item.name} className="flex items-center justify-between gap-2 text-xs"><span className="flex items-center gap-2 font-mono text-slate-300"><i className="size-2 rounded-full" style={{ background: severityColors[item.name] }} />{item.name}</span><strong className="font-mono text-slate-100">{item.value}</strong></div>)}
                </div>
              </div>
              <p className="sr-only">{severityData.map((item) => `${item.name} ${item.value}건`).join(", ")}</p>
            </>
          ) : <div className="mt-5"><EmptyMetric label="심각도 데이터 없음" /></div>}
        </article>
      </section>

      <section className="grid gap-5 2xl:grid-cols-[minmax(0,1.6fr)_minmax(19rem,0.6fr)]">
        <article className="signal-card min-h-[24rem] p-5 sm:p-6">
          <PanelTitle
            icon={BarChart3}
            title="시간대별 판정 추이"
            description="최초 탐지 시각을 기준으로 집계합니다."
            trailing={<span className="font-mono text-xs text-muted-foreground">{timezone}</span>}
          />
          {timelineData.length ? (
            <>
              <div className="mt-7 h-64 min-w-0">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={timelineData} margin={{ top: 8, right: 8, left: -24, bottom: 0 }} barCategoryGap="32.5%" accessibilityLayer>
                    <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#1b3038" />
                    <XAxis dataKey="label" tickLine={false} axisLine={false} tick={{ fill: "#8a9da7", fontSize: 12 }} />
                    <YAxis tickLine={false} axisLine={false} allowDecimals={false} tick={{ fill: "#8a9da7", fontSize: 12 }} />
                    <Tooltip cursor={false} formatter={(value, name) => [`${value}건`, name]} contentStyle={{ background: "#0c181e", border: "1px solid #213942", borderRadius: 10, fontSize: 13 }} />
                    <Bar dataKey="threat" name="위협 확인" fill="#ff6673" radius={[3, 3, 0, 0]} activeBar={false} isAnimationActive={false} />
                    <Bar dataKey="benign" name="비위협 판정" fill="#55d58b" radius={[3, 3, 0, 0]} activeBar={false} isAnimationActive={false} />
                    <Bar dataKey="inconclusive" name="결론 불충분" fill="#f5c451" radius={[3, 3, 0, 0]} activeBar={false} isAnimationActive={false} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
              <div className="mt-3 flex flex-wrap gap-4 text-xs text-muted-foreground">
                <span className="flex items-center gap-2"><i className="size-2 rounded-full bg-rose-400" />위협 확인</span>
                <span className="flex items-center gap-2"><i className="size-2 rounded-full bg-emerald-400" />비위협 판정</span>
                <span className="flex items-center gap-2"><i className="size-2 rounded-full bg-amber-400" />결론 불충분</span>
              </div>
            </>
          ) : <div className="mt-6"><EmptyMetric label="추이 데이터 없음" /></div>}
        </article>

        <article className="signal-card p-5 sm:p-6">
          <PanelTitle icon={Fingerprint} title="조사 데이터 품질" description="판정의 추적성과 신뢰도" />
          <div className="mt-6 space-y-5">
            {[
              ["근거 검증 완료", `${counts.verified} / ${counts.all}`, incidents.length ? counts.verified / incidents.length : 0, "bg-emerald-400"],
              ["평균 조사 확신도", percent(averageConfidence), averageConfidence, "bg-cyan-400"],
            ].map(([label, value, ratio, color]) => (
              <div key={String(label)}>
                <div className="flex items-center justify-between gap-3 text-sm"><span className="text-muted-foreground">{String(label)}</span><strong className="font-mono text-slate-100">{String(value)}</strong></div>
                <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-white/6"><div className={`h-full rounded-full ${String(color)}`} style={{ width: percent(Number(ratio)) }} /></div>
              </div>
            ))}
            <div className="rounded-xl border border-white/8 bg-white/[0.025] p-4">
              <p className="text-xs text-muted-foreground">원본 로그 참조</p>
              <p className="mt-2 font-mono text-2xl font-semibold text-violet-300">{rawReferenceCount.toLocaleString()}</p>
              <p className="mt-1 text-xs leading-5 text-muted-foreground">판정 근거에서 역추적 가능한 로그 줄 수</p>
            </div>
          </div>
        </article>
      </section>
    </div>
  );
}

function TechniqueCell({ incident }: { incident: Incident }) {
  const mapping = attackMappingOf(incident);
  if (!mapping) return <span className="text-xs text-slate-500">매핑 전</span>;
  if (!mapping.techniques.length) {
    return <span className="text-xs text-muted-foreground">{mappingStatusMeta[mapping.status]?.label ?? mapping.status}</span>;
  }
  return (
    <span className="flex max-w-[13rem] flex-wrap gap-1" title={mapping.techniques.map((item) => `${item.id} ${item.name} (${item.tactic})`).join("\n")}>
      {mapping.techniques.slice(0, 2).map((item) => <span key={item.id} className="rounded border border-cyan-400/20 bg-cyan-400/5 px-1.5 py-0.5 font-mono text-[0.7rem] text-cyan-200">{item.id}</span>)}
      {mapping.techniques.length > 2 && <span className="text-[0.7rem] text-muted-foreground">+{mapping.techniques.length - 2}</span>}
    </span>
  );
}

function IncidentList({ incidents, onOpenIncident, filterPreset, timezone }: { incidents: Incident[]; onOpenIncident: (item: Incident) => void; filterPreset: IncidentFilterPreset; timezone: Timezone }) {
  const [query, setQuery] = useState("");
  const [verdict, setVerdict] = useState<IncidentVerdictFilter>(filterPreset.verdict);
  const [severity, setSeverity] = useState<IncidentSeverityFilter>(filterPreset.severity);
  const hasFilters = Boolean(query) || verdict !== "ALL" || severity !== "ALL";

  const filtered = useMemo(() => incidents.filter((item) => {
    const techniques = (attackMappingOf(item)?.techniques ?? []).map((technique) => `${technique.id} ${technique.name}`).join(" ");
    const text = `${item.incidentId} ${item.title} ${item.host} ${item.srcIp} ${item.summary} ${techniques}`.toLowerCase();
    const severityMatches = severity === "ALL"
      || (severity === "URGENT" ? ["CRITICAL", "HIGH"].includes(item.severity) : item.severity === severity);
    return text.includes(query.toLowerCase()) && (verdict === "ALL" || item.verdict === verdict) && severityMatches;
  }), [incidents, query, severity, verdict]);

  return (
    <section className="signal-card overflow-hidden">
      <div className="border-b border-white/8 p-5 sm:p-6">
        <PanelTitle
          icon={ListTree}
          title="사건 목록"
          description={`${filtered.length}건 표시 · 전체 ${incidents.length}건`}
          trailing={hasFilters ? (
            <button
              type="button"
              onClick={() => { setQuery(""); setVerdict("ALL"); setSeverity("ALL"); }}
              className="inline-flex min-h-10 items-center gap-2 rounded-lg border border-white/10 px-3 text-sm text-muted-foreground transition hover:border-cyan-400/30 hover:text-cyan-200"
            >
              <RotateCcw aria-hidden="true" className="size-4" />
              <span className="hidden sm:inline">필터 초기화</span>
            </button>
          ) : undefined}
        />
        <div className="mt-5 grid gap-3 md:grid-cols-[minmax(0,1fr)_170px_150px]">
          <div className="relative">
            <Search aria-hidden="true" className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-slate-400" />
            <Input aria-label="사건 검색" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="사건 ID, IP, 호스트, 공격 유형, ATT&CK 기법 검색" className="h-11 border-white/10 bg-black/15 pl-10" />
          </div>
          <Select value={verdict} onValueChange={(value) => setVerdict(value as IncidentVerdictFilter)}>
            <SelectTrigger aria-label="판정 필터" className="h-11 w-full border-white/10 bg-black/15 font-medium text-slate-200 hover:border-cyan-400/25 hover:bg-cyan-400/[0.035]">
              <SelectValue placeholder="판정 선택" />
            </SelectTrigger>
            <SelectContent position="popper" align="start" className="border-white/10 bg-[#0b171d] font-sans text-slate-200 shadow-2xl shadow-black/50">
              <SelectItem value="ALL">모든 판정</SelectItem>
              <SelectItem value="THREAT_CONFIRMED">위협 확인</SelectItem>
              <SelectItem value="FALSE_POSITIVE">비위협 판정</SelectItem>
              <SelectItem value="INCONCLUSIVE">결론 불충분</SelectItem>
            </SelectContent>
          </Select>
          <Select value={severity} onValueChange={(value) => setSeverity(value as IncidentSeverityFilter)}>
            <SelectTrigger aria-label="심각도 필터" className="h-11 w-full border-white/10 bg-black/15 font-medium text-slate-200 hover:border-cyan-400/25 hover:bg-cyan-400/[0.035]">
              <SelectValue placeholder="심각도 선택" />
            </SelectTrigger>
            <SelectContent position="popper" align="start" className="border-white/10 bg-[#0b171d] font-sans text-slate-200 shadow-2xl shadow-black/50">
              <SelectItem value="ALL">모든 심각도</SelectItem>
              <SelectItem value="URGENT">CRITICAL · HIGH</SelectItem>
              {Object.keys(severityOrder).map((item) => <SelectItem key={item} value={item}>{item}</SelectItem>)}
            </SelectContent>
          </Select>
        </div>
        <p className="sr-only" aria-live="polite">검색 결과 {filtered.length}건</p>
      </div>

      <div className="divide-y divide-white/7 md:hidden">
        {filtered.map((incident) => (
          <button
            type="button"
            key={incident.sourceFile}
            onClick={() => onOpenIncident(incident)}
            className="group block w-full p-5 text-left transition hover:bg-cyan-400/[0.035]"
          >
            <span className="flex items-start justify-between gap-3">
              <span className="flex min-w-0 flex-wrap items-center gap-2">
                <SeverityBadge severity={incident.severity} />
                <span className="font-mono text-xs text-cyan-300">{incident.incidentId}</span>
              </span>
              <span className="shrink-0 font-mono text-xs text-muted-foreground">{formatDate(incident.triggerTime, timezone)}</span>
            </span>
            <span className="mt-3 block truncate text-sm font-semibold text-slate-100">{incident.title}</span>
            <span className="mt-2 flex items-center justify-between gap-3">
              <span className="truncate text-xs text-muted-foreground">{incident.host} · {incident.srcIp}</span>
              <ChevronRight aria-hidden="true" className="size-4 shrink-0 text-slate-500 transition group-hover:translate-x-1 group-hover:text-cyan-300" />
            </span>
            <span className="mt-3 flex items-center justify-between gap-3">
              <VerdictLabel verdict={incident.verdict} />
              <ProvenanceBadge status={incident.provenance.status} />
            </span>
          </button>
        ))}
      </div>

      <Table className="hidden min-w-[900px] md:table">
        <TableHeader>
          <TableRow className="border-white/8 bg-white/[0.025] hover:bg-white/[0.025]">
            <TableHead scope="col" className="px-5 text-xs text-muted-foreground">사건</TableHead>
            <TableHead scope="col" className="text-xs text-muted-foreground">심각도</TableHead>
            <TableHead scope="col" className="text-xs text-muted-foreground">판정</TableHead>
            <TableHead scope="col" className="text-xs text-muted-foreground">대상 / 출발지</TableHead>
            <TableHead scope="col" className="text-xs text-muted-foreground">ATT&CK</TableHead>
            <TableHead scope="col" className="text-xs text-muted-foreground">증거</TableHead>
            <TableHead scope="col" className="text-xs text-muted-foreground">근거 상태</TableHead>
            <TableHead scope="col" className="pr-5 text-right text-xs text-muted-foreground">탐지 시각</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {filtered.map((incident) => (
            <TableRow key={incident.sourceFile} onClick={() => onOpenIncident(incident)} className="cursor-pointer border-white/7 hover:bg-cyan-400/[0.035]">
              <TableCell className="max-w-[26rem] px-5 py-4">
                <button type="button" onClick={(event) => { event.stopPropagation(); onOpenIncident(incident); }} className="block w-full rounded text-left">
                  <span className="block font-mono text-xs text-cyan-300">{incident.incidentId}</span>
                  <span className="mt-1.5 block truncate font-medium text-slate-200">{incident.title}</span>
                  <span className="mt-1 block max-w-[26rem] truncate text-xs text-muted-foreground">{incident.summary}</span>
                </button>
              </TableCell>
              <TableCell><SeverityBadge severity={incident.severity} /></TableCell>
              <TableCell><VerdictLabel verdict={incident.verdict} /></TableCell>
              <TableCell>
                <p className="text-sm text-slate-300">{incident.host}</p>
                <p className="mt-1 font-mono text-xs text-muted-foreground">{incident.srcIp}</p>
              </TableCell>
              <TableCell><TechniqueCell incident={incident} /></TableCell>
              <TableCell className="font-mono text-xs text-muted-foreground">+{incident.evidence.length} / −{incident.contradictingEvidence.length}</TableCell>
              <TableCell><ProvenanceBadge status={incident.provenance.status} /></TableCell>
              <TableCell className="pr-5 text-right font-mono text-xs text-muted-foreground">{formatDate(incident.triggerTime, timezone)}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      {!filtered.length && <div className="p-12 text-center"><Search className="mx-auto size-6 text-slate-500" /><p className="mt-3 text-sm font-medium text-slate-300">조건에 맞는 사건이 없습니다.</p><p className="mt-1 text-xs text-muted-foreground">검색어나 필터를 변경해 보세요.</p></div>}
    </section>
  );
}

function DetectionTable({ detections, onOpenResult, timezone, initialState = "ALL" }: { detections: Detection[]; onOpenResult: (resultKey: string) => void; timezone: Timezone; initialState?: string }) {
  const [query, setQuery] = useState("");
  const [sortBy, setSortBy] = useState("score");
  const [priority, setPriority] = useState("ALL");
  const [state, setState] = useState(initialState);
  const filtered = useMemo(() => {
    const timestampOf = (item: Detection) => {
      const timestamp = new Date(item.updatedAt).getTime();
      return Number.isNaN(timestamp) ? 0 : timestamp;
    };
    const tieBreak = (a: Detection, b: Detection) => b.score - a.score
      || timestampOf(b) - timestampOf(a)
      || a.incidentId.localeCompare(b.incidentId);

    return detections.filter((item) => {
      const text = `${item.incidentId} ${item.incidentKey} ${item.entityValue} ${item.rules.join(" ")} ${item.llmReason}`.toLowerCase();
      return text.includes(query.toLowerCase())
        && (priority === "ALL" || (priority === "P1P2" ? ["P1", "P2"].includes(item.priority) : item.priority === priority))
        && (state === "ALL" || item.state === state);
    }).sort((a, b) => {
      if (sortBy === "time") return timestampOf(b) - timestampOf(a) || tieBreak(a, b);
      return tieBreak(a, b);
    });
  }, [detections, priority, query, sortBy, state]);

  return (
    <section className="signal-card overflow-hidden">
      <div className="border-b border-white/8 p-5 sm:p-6">
        <PanelTitle icon={Database} title="탐지·대기열" description={`1차 탐지 DB의 사건 ${filtered.length}건 표시 · 전체 ${detections.length}건 (조사 전 사건 포함)`} trailing={<TriageLegend />} />
        <div className="mt-5 grid gap-3 md:grid-cols-[minmax(0,1fr)_150px_170px_190px]">
          <div className="relative">
            <Search aria-hidden="true" className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-slate-400" />
            <Input aria-label="탐지 사건 검색" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="IP, pid, 사건 ID, 탐지 룰, Haiku 의견 검색" className="h-11 border-white/10 bg-black/15 pl-10" />
          </div>
          <Select value={sortBy} onValueChange={setSortBy}>
            <SelectTrigger aria-label="탐지 사건 정렬" className="h-11 w-full border-white/10 bg-black/15 font-medium text-slate-200 hover:border-cyan-400/25 hover:bg-cyan-400/[0.035]">
              <SelectValue placeholder="정렬 선택" />
            </SelectTrigger>
            <SelectContent position="popper" align="start" className="border-white/10 bg-[#0b171d] font-sans text-slate-200 shadow-2xl shadow-black/50">
              <SelectItem value="score">점수순</SelectItem>
              <SelectItem value="time">시간대순</SelectItem>
            </SelectContent>
          </Select>
          <Select value={priority} onValueChange={setPriority}>
            <SelectTrigger aria-label="우선순위 필터" className="h-11 w-full border-white/10 bg-black/15 font-medium text-slate-200 hover:border-cyan-400/25 hover:bg-cyan-400/[0.035]">
              <SelectValue placeholder="우선순위 선택" />
            </SelectTrigger>
            <SelectContent position="popper" align="start" className="border-white/10 bg-[#0b171d] font-sans text-slate-200 shadow-2xl shadow-black/50">
              <SelectItem value="ALL">모든 우선순위</SelectItem>
              <SelectItem value="P1P2">P1·P2 (조사 대상)</SelectItem>
              {["P1", "P2", "P3", "P4"].map((item) => <SelectItem key={item} value={item}>{item}</SelectItem>)}
            </SelectContent>
          </Select>
          <Select value={state} onValueChange={setState}>
            <SelectTrigger aria-label="상태 필터" className="h-11 w-full border-white/10 bg-black/15 font-medium text-slate-200 hover:border-cyan-400/25 hover:bg-cyan-400/[0.035]">
              <SelectValue placeholder="상태 선택" />
            </SelectTrigger>
            <SelectContent position="popper" align="start" className="border-white/10 bg-[#0b171d] font-sans text-slate-200 shadow-2xl shadow-black/50">
              <SelectItem value="ALL">모든 상태</SelectItem>
              {Object.entries(detectionStateMeta).map(([key, meta]) => <SelectItem key={key} value={key}>{meta.label}</SelectItem>)}
            </SelectContent>
          </Select>
        </div>
      </div>
      <div>
        <Table className="min-w-[900px] table-fixed">
          <TableHeader>
            <TableRow className="border-white/8 bg-white/[0.025] hover:bg-white/[0.025]">
              <TableHead scope="col" className="w-[11rem] px-5 text-xs text-muted-foreground">우선순위 · 점수</TableHead>
              <TableHead scope="col" className="w-[13rem] text-xs text-muted-foreground">대상</TableHead>
              <TableHead scope="col" className="text-xs text-muted-foreground">걸린 탐지 룰</TableHead>
              <TableHead scope="col" className="text-xs text-muted-foreground">Haiku 1차 의견</TableHead>
              <TableHead scope="col" className="w-[9.5rem] text-xs text-muted-foreground">상태 · 탐지 갱신</TableHead>
              <TableHead scope="col" className="w-[5.5rem] pr-5 text-right text-xs text-muted-foreground">조사 결과</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {filtered.map((item) => {
              const stateMeta = detectionStateMeta[item.state] ?? detectionStateMeta.queued;
              return (
                <TableRow key={item.incidentKey} className="border-white/7">
                  <TableCell className="px-5 py-4"><span className="flex items-center gap-3"><span className={`w-6 font-mono text-sm font-bold ${priorityStyle[item.priority] ?? "text-slate-300"}`}>{item.priority}</span><TriageScoreBar score={item.score} parts={item.parts} /></span></TableCell>
                  <TableCell>
                    <p className="truncate font-mono text-sm text-slate-200" title={item.entityValue}>{item.entityType === "src_ip" ? "IP" : item.entityType} {item.entityValue}</p>
                    <p className="mt-1 truncate font-mono text-xs text-muted-foreground">{item.incidentId} · {item.layers.join(" · ") || "-"}</p>
                  </TableCell>
                  <TableCell>
                    <p className="truncate text-sm text-slate-300" title={item.rules.join("\n")}>{item.rules[0] ?? "-"}</p>
                    {item.rules.length > 1 && <p className="mt-1 text-xs text-muted-foreground">외 {item.rules.length - 1}종 · 탐지 {item.ruleCount}건</p>}
                  </TableCell>
                  <TableCell>
                    {item.llmInvestigate === null
                      ? <span className="text-xs text-slate-500">검토 안 함</span>
                      : item.llmInvestigate
                        ? <span className="text-xs font-semibold text-rose-300">조사 필요</span>
                        // 결정론 점수로는 P1인데 Haiku가 오탐으로 본 사건은 사람이 한 번 더 확인하도록 강조합니다.
                        : item.priority === "P1"
                          ? <span className="text-xs font-semibold text-amber-300" title="결정론 점수로는 P1인데 Haiku가 오탐으로 봐서 대기열에서 빠졌습니다.">오탐 의견 · P1 확인 필요</span>
                          : <span className="text-xs font-semibold text-emerald-300">오탐 의견</span>}
                    {item.llmReason && <p className="mt-1 truncate text-xs text-muted-foreground" title={item.llmReason}>{item.llmReason}</p>}
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline" className={stateMeta.style}>{stateMeta.label}</Badge>
                    {item.hasUpdate && <p className="mt-1 text-xs text-amber-300">조사 중 새 활동</p>}
                    <p className="mt-1.5 font-mono text-[0.7rem] text-muted-foreground">{formatDate(item.updatedAt, timezone)}</p>
                  </TableCell>
                  <TableCell className="pr-5 text-right">
                    {item.investigated
                      ? <button type="button" onClick={() => onOpenResult(item.resultKey)} className="inline-flex items-center gap-1 rounded-lg border border-cyan-400/25 px-2.5 py-1 text-xs text-cyan-200 transition hover:bg-cyan-400/10">열기<ChevronRight aria-hidden="true" className="size-3.5" /></button>
                      : <span className="text-xs text-slate-500">-</span>}
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      </div>
      {!filtered.length && <div className="p-12 text-center text-sm text-muted-foreground">조건에 맞는 탐지 사건이 없습니다.</div>}
    </section>
  );
}

function IncidentsView({ incidents, pipeline, onOpenIncident, onOpenResult, filterPreset, viewPreset, timezone }: { incidents: Incident[]; pipeline: PipelineData | null; onOpenIncident: (item: Incident) => void; onOpenResult: (resultKey: string) => void; filterPreset: IncidentFilterPreset; viewPreset: IncidentViewPreset; timezone: Timezone }) {
  const [tab, setTab] = useState<"results" | "detections">(viewPreset.tab);
  const hasDetections = Boolean(pipeline?.enabled && pipeline.connected);
  if (!hasDetections || !pipeline) return <IncidentList incidents={incidents} onOpenIncident={onOpenIncident} filterPreset={filterPreset} timezone={timezone} />;
  return (
    <div className="space-y-4">
      <div className="inline-flex rounded-xl border border-white/10 bg-black/20 p-1" role="tablist" aria-label="사건 보기 선택">
        {([["results", `조사 결과 (${incidents.length})`], ["detections", `탐지·대기열 (${pipeline.detections.length})`]] as const).map(([key, label]) => (
          <button type="button" key={key} role="tab" aria-selected={tab === key} onClick={() => setTab(key)} className={`min-h-9 rounded-lg px-4 text-sm font-semibold transition ${tab === key ? "bg-cyan-300 text-[#041112]" : "text-muted-foreground hover:text-foreground"}`}>{label}</button>
        ))}
      </div>
      {tab === "results"
        ? <IncidentList incidents={incidents} onOpenIncident={onOpenIncident} filterPreset={filterPreset} timezone={timezone} />
        : <DetectionTable detections={pipeline.detections} onOpenResult={onOpenResult} timezone={timezone} initialState={viewPreset.detectionState} />}
    </div>
  );
}

function IncidentGraph({ incident, timezone }: { incident: Incident; timezone: Timezone }) {
  const nodes = useMemo(() => {
    const sourceNodes = incident.srcIp ? [{ id: `source-${incident.srcIp}`, kind: "source", label: "출발지", title: incident.srcIp, detail: incident.detectionSource || "외부 접근 주체", icon: Network, color: "rose" }] : [];
    const eventNodes = incident.timeline.length
      ? incident.timeline.map((item, index) => ({ id: `timeline-${index}-${item.time}`, kind: "event", label: `이벤트 ${index + 1}`, title: item.event, detail: [item.source, formatDate(item.time, timezone)].filter(Boolean).join(" · "), icon: Activity, color: index % 2 ? "cyan" : "amber" }))
      : [...incident.evidence, ...incident.contradictingEvidence]
          .sort((a, b) => a.sequence - b.sequence)
          .map((item) => ({ id: `evidence-${item.id}`, kind: "event", label: item.stance === "supporting" ? "지지 증거" : "반박 증거", title: item.description, detail: `${item.layer} · ${item.eventType}`, icon: Fingerprint, color: item.stance === "supporting" ? "cyan" : "amber" }));
    const systems = incident.affectedSystems.length ? incident.affectedSystems : incident.host ? [incident.host] : [];
    const targetNodes = [...new Set(systems)].map((system) => ({ id: `target-${system}`, kind: "target", label: "영향 시스템", title: system, detail: incident.title, icon: Server, color: "violet" }));
    return [...sourceNodes, ...eventNodes, ...targetNodes];
  }, [incident, timezone]);
  const [active, setActive] = useState(0);
  const relationshipLabel = (index: number) => {
    const current = nodes[index];
    const next = nodes[index + 1];
    if (!current || !next) return "";
    if (next.kind === "target") return "대상 연결";
    if (current.kind === "source") return "활동 시작";
    if (/종료|완료|총\s*\d+|집계/.test(next.title)) return "결과 집계";
    if (/명령|실행|프로세스|쉘/.test(next.title)) return "후속 실행";
    if (/접근|스캔|탐색|요청/.test(next.title)) {
      return /접근|스캔|탐색|요청/.test(current.title) ? "연속 요청" : "탐색 확장";
    }
    return "시간 순서";
  };
  const selected = nodes[active];
  if (!selected) return null;
  const SelectedIcon = selected.icon;
  return <section className="attack-graph signal-card p-5">
    <div><h3 className="font-semibold">사건 연결 관계</h3><p className="mt-1 text-xs text-muted-foreground">노드 사이의 관계를 따라 사건 흐름을 확인합니다. 그래프는 가로로 스크롤할 수 있습니다.</p></div>
    <div
      className="attack-graph__viewport mt-5"
      tabIndex={0}
      aria-label="사건 연결 관계 그래프. 좌우로 스크롤하여 모든 노드를 확인할 수 있습니다."
    >
      <div className="attack-graph__stage" style={{ minWidth: `${Math.max(960, nodes.length * 245)}px` }}><div className="flex items-center">
      {nodes.map((node, index) => { const Icon = node.icon; return <div key={node.id} className="flex min-w-0 flex-1 items-center">
        <button type="button" onClick={() => setActive(index)} className={`attack-node attack-node--${node.color} ${active === index ? "is-active" : ""}`} aria-pressed={active === index}>
          <span className="attack-node__icon"><Icon className="size-5" /></span><span className="text-left"><small>{node.label}</small><strong>{node.title}</strong><em>{node.detail}</em></span>
        </button>
        {index < nodes.length - 1 && <div className="attack-edge"><span>{relationshipLabel(index)}</span><i /></div>}
      </div>; })}
      </div></div>
    </div>
    <div className="mt-4 flex items-center gap-3 rounded-lg border border-white/8 bg-black/20 p-3"><span className="grid size-10 shrink-0 place-items-center rounded-lg bg-cyan-400/10 text-cyan-300"><SelectedIcon className="size-5" /></span><div className="min-w-0"><p className="text-xs text-muted-foreground">선택한 노드 · {selected.label}</p><p className="mt-1 truncate text-sm font-semibold">{selected.title}</p><p className="mt-1 line-clamp-2 text-xs leading-5 text-muted-foreground">{selected.detail}</p></div></div>
  </section>;
}

function EvidenceMappingBadge({ mapping }: { mapping: EvidenceMapping }) {
  if (!mapping || !evidenceMappingMeta[mapping.state]) return null;
  const meta = evidenceMappingMeta[mapping.state];
  const detail = mapping.state === "mapped"
    ? ` ${mapping.techniques.join(", ")}`
    : "";
  const title = mapping.reasons.length ? mapping.reasons.map((code) => exclusionReasonLabel[code] ?? code).join(", ") : undefined;
  return <Badge variant="outline" title={title} className={`font-mono text-[0.7rem] ${meta.style}`}>ATT&CK {meta.label}{detail}</Badge>;
}

function TechniqueLink({ id, selected = false }: { id: string; selected?: boolean }) {
  const href = attackUrl(id);
  const style = selected
    ? "border-emerald-400/30 bg-emerald-400/10 text-emerald-200"
    : "border-white/10 bg-white/[0.03] text-slate-300";
  const className = `inline-flex rounded-md border px-2 py-0.5 font-mono text-xs ${style}`;
  return href
    ? <a href={href} target="_blank" rel="noopener noreferrer" className={`${className} hover:border-cyan-400/40 hover:text-cyan-200`}>{id}</a>
    : <span className={className}>{id}</span>;
}

function AttackMappingPanel({ incident, timezone }: { incident: Incident; timezone: Timezone }) {
  const mapping = attackMappingOf(incident);
  if (!mapping) {
    return <article className="signal-card p-5">
      <div className="flex items-center gap-2"><Network className="size-4 text-violet-300" /><h3 className="font-semibold">ATT&CK 매핑</h3></div>
      <p className="mt-3 text-sm leading-6 text-muted-foreground">이 사건은 조사 결과만 있고 매핑 결과가 없습니다. 조사 에이전트가 저장한 결과 파일로 <code className="text-xs text-cyan-200">python -m attack_mapping.cli &lt;조사 결과 파일&gt;</code>을 실행하면 매핑됩니다.</p>
    </article>;
  }
  const status = mappingStatusMeta[mapping.status] ?? { label: mapping.status, style: mappingStatusMeta.deferred.style };
  const methodLabel = mapping.method.toLowerCase().includes("rag") ? "RAG + 근거 검증" : mapping.method;
  return (
    <div className="space-y-5">
      <section className="signal-card p-5">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <div className="flex items-center gap-2"><Network className="size-4 text-violet-300" /><h3 className="font-semibold">ATT&CK 매핑</h3></div>
            <p className="mt-1 text-xs leading-5 text-muted-foreground">증거마다 공식 ATT&CK {mapping.attackVersion}에서 RAG로 후보 10개를 검색하고, 근거가 있는 기법만 선택한 뒤 코드가 ID와 증거 연결을 다시 검증했습니다.</p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <Badge variant="outline" className={status.style}>{status.label}</Badge>
            <Badge variant="outline" className="border-violet-400/20 bg-violet-400/[0.05] text-[0.7rem] text-violet-200">{methodLabel}</Badge>
          </div>
        </div>
        {mapping.errors.length > 0 && <div className="mt-4 rounded-lg border border-rose-400/20 bg-rose-400/5 p-3 text-xs leading-5 text-rose-200">{mapping.errors.map((error) => <p key={error}>{error}</p>)}</div>}
        {mapping.killChain.length > 0 && (
          <div className="mt-5 flex flex-wrap items-stretch gap-2 border-t border-white/8 pt-5">
            {mapping.killChain.map((step, index) => (
              <div key={`${step.step}-${step.techniqueId}`} className="flex items-center gap-2">
                {index > 0 && <ArrowRight aria-hidden="true" className="size-4 shrink-0 text-slate-500" />}
                <div className="min-w-44 rounded-lg border border-violet-400/20 bg-violet-400/[0.06] p-3">
                  <p className="text-[0.7rem] font-semibold uppercase tracking-[0.12em] text-violet-300">{step.step}. {step.tactic}</p>
                  <p className="mt-1.5 text-sm"><span className="font-mono font-semibold text-cyan-200">{step.techniqueId}</span> <span className="text-slate-200">{step.techniqueName}</span></p>
                  <p className="mt-1 font-mono text-[0.7rem] text-muted-foreground">{formatDate(step.time, timezone)} {timezone} · {step.evidenceIds.join(", ")}</p>
                </div>
              </div>
            ))}
          </div>
        )}
      </section>

      {mapping.techniques.length > 0 && (
        <section className="signal-card overflow-hidden border-violet-400/15">
          <div className="border-b border-violet-400/12 bg-violet-400/[0.035] p-5">
            <div className="flex items-center gap-2 text-violet-200"><Network className="size-4" /><h3 className="text-sm font-semibold">증거 기반 ATT&CK 매핑</h3></div>
            <p className="mt-1 text-xs text-muted-foreground">기법 정보와 해당 기법을 뒷받침한 증거의 매핑 근거입니다.</p>
          </div>
          <div className="grid gap-4 p-4 xl:grid-cols-2">
          {mapping.techniques.map((technique) => (
            <article key={technique.id} className="rounded-xl border border-violet-400/15 bg-violet-400/[0.025] p-5">
              <div className="flex flex-wrap items-center gap-2">
                <TechniqueLink id={technique.id} />
                <h4 className="font-semibold text-slate-100">{technique.name}</h4>
                <Badge variant="outline" className="border-violet-400/20 text-violet-300">{technique.tactic}</Badge>
              </div>
              <p className="mt-2 text-xs text-muted-foreground">{technique.parent && <>상위 기법 {technique.parent} · </>}근거 증거 {technique.evidenceIds.join(", ")}</p>
              <div className="mt-4 space-y-3">
                {technique.reasons.map((item, index) => (
                  <div key={`${technique.id}-${index}`} className="rounded-lg border-l-2 border-cyan-400/30 bg-black/15 px-3 py-2">
                    <p className="font-mono text-[0.7rem] text-cyan-300">{item.evidenceIds.join(", ")} · 매핑 근거</p>
                    <p className="mt-1 text-sm leading-6 text-slate-300">{item.reason}</p>
                  </div>
                ))}
              </div>
            </article>
          ))}
          </div>
        </section>
      )}

      {mapping.trace.length > 0 && (
        <section className="signal-card overflow-hidden border-cyan-400/15">
          <div className="border-b border-cyan-400/12 bg-cyan-400/[0.025] p-5">
            <div className="flex items-center gap-2 text-cyan-200"><Fingerprint className="size-4" /><h3 className="text-sm font-semibold">증거별 검색 후보와 선택</h3></div>
            <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
              <span className="flex items-center gap-1.5"><b aria-hidden="true" className="text-sm leading-none text-emerald-300">○</b>초록색 증거: 매핑 기법 있음</span>
              <span className="flex items-center gap-1.5"><b aria-hidden="true" className="text-sm leading-none text-amber-300">×</b>주황색 증거: 매핑 기법 없음</span>
              <span className="flex items-center gap-1.5"><i className="size-2 rounded-full border border-emerald-400 bg-emerald-400/15" />초록색 기법: 최종 선택·검증 통과</span>
            </div>
          </div>
          <div className="grid gap-2 border-b border-white/8 bg-black/15 px-4 py-2.5 text-[0.7rem] font-semibold uppercase tracking-[0.1em] text-slate-500 sm:grid-cols-[7rem_minmax(0,1fr)]"><span>증거</span><span>Top 10 후보 기법</span></div>
          <div className="divide-y divide-white/7">
            {mapping.trace.map((unit) => (
              <div key={unit.evidenceId} className="grid gap-2 p-4 sm:grid-cols-[7rem_minmax(0,1fr)]">
                <div><p className={`flex items-center gap-1.5 font-mono text-xs font-semibold ${unit.selected.length ? "text-emerald-300" : "text-amber-300"}`}><span aria-hidden="true" className="text-sm leading-none">{unit.selected.length ? "○" : "×"}</span>{unit.evidenceId}</p></div>
                <div className="flex flex-wrap gap-1.5">{unit.candidates.map((candidate) => <TechniqueLink key={candidate} id={candidate} selected={unit.selected.includes(candidate)} />)}</div>
              </div>
            ))}
          </div>
        </section>
      )}

      {(mapping.exclusions.length > 0 || mapping.rejected.length > 0) && (
        <section className="rounded-xl border border-white/7 bg-black/10 p-4">
          {mapping.exclusions.length > 0 && <div><h3 className="text-sm font-semibold text-slate-300">매핑에서 뺀 증거</h3><p className="mt-1 text-xs leading-5 text-muted-foreground">원본 참조가 없거나 검증에 문제가 있거나, 조회 결과가 비어 있어 ATT&CK 행위를 직접 뒷받침하기 어려운 증거입니다.</p><div className="mt-3 flex flex-wrap gap-2">{mapping.exclusions.map((item) => <span key={item.evidenceId} title={item.reasons.map((code) => exclusionReasonLabel[code] ?? code).join(", ")} className="rounded-md border border-slate-500/15 bg-slate-500/[0.04] px-2.5 py-1 font-mono text-[0.7rem] text-slate-500">{item.evidenceId}</span>)}</div></div>}
          {mapping.rejected.length > 0 && <div className={`${mapping.exclusions.length ? "mt-4 border-t border-white/7 pt-4" : ""}`}><h3 className="text-sm font-semibold text-slate-300">검증에서 거부된 선택</h3><div className="mt-3 flex flex-wrap gap-2">{mapping.rejected.map((item, index) => <span key={`${item.evidenceId}-${index}`} className="rounded-md border border-rose-400/12 bg-rose-400/[0.035] px-2.5 py-1 font-mono text-[0.7rem] text-rose-300/70">{item.evidenceId} · {item.value} · {item.code}</span>)}</div></div>}
        </section>
      )}
    </div>
  );
}

function TriageCard({ incident, timezone }: { incident: Incident; timezone: Timezone }) {
  const triage = triageOf(incident);
  if (!triage) return null;
  const detected = new Date(triage.updatedAt).getTime();
  const investigated = new Date(incident.timestamp).getTime();
  const delayHours = Number.isNaN(detected) || Number.isNaN(investigated) ? null : (investigated - detected) / 3_600_000;
  return (
    <section className="signal-card p-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2"><Bot className="size-4 text-orange-300" /><h3 className="text-sm font-semibold">1차 탐지 · 트리아지</h3></div>
        <TriageLegend parts={triage.parts} />
      </div>
      <div className="mt-4 grid gap-4 md:grid-cols-3">
        <div><p className="text-xs text-muted-foreground">우선순위 · 점수</p><div className="mt-2 flex items-center gap-3"><span className={`font-mono text-lg font-bold ${priorityStyle[triage.priority] ?? "text-slate-300"}`}>{triage.priority}</span><TriageScoreBar score={triage.score} parts={triage.parts} wide /></div></div>
        <div><p className="text-xs text-muted-foreground">Haiku 1차 의견</p><p className={`mt-2 text-sm font-semibold ${triage.llmInvestigate === null ? "text-slate-400" : triage.llmInvestigate ? "text-rose-300" : "text-emerald-300"}`}>{triage.llmInvestigate === null ? "검토 안 함" : triage.llmInvestigate ? "조사 필요" : "오탐 의견"}</p>{triage.llmReason && <p className="mt-1 text-xs leading-5 text-muted-foreground">{triage.llmReason}</p>}</div>
        <div><p className="text-xs text-muted-foreground">탐지 갱신 → 조사</p><p className="mt-2 font-mono text-sm text-slate-200">{formatDate(triage.updatedAt, timezone)} → {formatDate(incident.timestamp, timezone)} {timezone}</p>{delayHours !== null && (delayHours < 0
          // 조사가 끝난 뒤 같은 사건에 새 활동이 생기면 DB 갱신 시각이 조사 시각보다 늦어집니다.
          ? <p className="mt-1 text-xs text-amber-300">조사 이후 새 활동으로 사건이 갱신됨 · 다시 조사 대상일 수 있음</p>
          : <p className={`mt-1 text-xs ${delayHours >= 6 ? "text-amber-300" : "text-muted-foreground"}`}>{delayHours >= 6 ? "⚠ " : ""}{delayHours.toFixed(1)}시간 뒤 조사</p>)}</div>
      </div>
      {triage.rules.length > 0 && <div className="mt-4 flex flex-wrap gap-2">{triage.rules.map((rule) => <Badge key={rule} variant="outline" className="border-white/10 text-slate-300">{rule}</Badge>)}</div>}
    </section>
  );
}

const autonomyStyle: Record<string, string> = {
  L0: "border-amber-400/25 bg-amber-400/8 text-amber-200",
  L1: "border-violet-400/25 bg-violet-400/8 text-violet-200",
  L2: "border-cyan-400/25 bg-cyan-400/8 text-cyan-200",
};

const autonomyTextStyle: Record<string, string> = {
  L0: "text-amber-300",
  L1: "text-violet-300",
  L2: "text-cyan-300",
};

const riskLabel: Record<string, string> = {
  LOW: "낮음",
  MED: "중간",
  MEDIUM: "중간",
  HIGH: "높음",
};

// 사건 심각도 색상 중 서로 가까운 HIGH(주황)는 빼고,
// 조치 위험도 3단계를 CRITICAL(장미) · MEDIUM(황색) · LOW(청색)에 대응시킵니다.
const riskStyle: Record<string, string> = {
  HIGH: severityStyle.CRITICAL,
  MED: severityStyle.MEDIUM,
  MEDIUM: severityStyle.MEDIUM,
  LOW: severityStyle.LOW,
};

function ResponsePanel({ incident }: { incident: Incident }) {
  const response = responseOf(incident);
  if (!response) {
    return (
      <section className="signal-card p-8 text-center">
        <WifiOff aria-hidden="true" className="mx-auto size-7 text-slate-500" />
        <h3 className="mt-4 text-sm font-semibold text-slate-200">연결된 대응 권고가 없습니다</h3>
        <p className="mx-auto mt-2 max-w-xl text-sm leading-6 text-muted-foreground">이 사건과 일치하는 response JSON이 아직 생성되지 않았습니다.</p>
      </section>
    );
  }

  const immediateCount = response.actions.filter((action) => action.category === "immediate").length;
  const verifyCount = response.actions.filter((action) => action.category === "verify_needed").length;
  const actions = response.actions.slice().sort((a, b) => a.priority - b.priority || a.id.localeCompare(b.id));

  return (
    <div className="space-y-5">
      <section className="signal-card p-5">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <Badge variant="outline" className="border-emerald-400/25 bg-emerald-400/8 text-emerald-200">{response.statusLabel}</Badge>
              <span className="text-xs text-muted-foreground">사건별 대응 결과</span>
            </div>
            <h3 className="mt-4 text-base font-semibold text-slate-100">권고 조치 {response.actions.length}건</h3>
            <p className="mt-2 text-sm leading-6 text-muted-foreground">{response.summary || "조사 판정과 ATT&CK 매핑을 바탕으로 생성된 최종 대응 권고입니다."}</p>
          </div>
          <div className="grid min-w-48 grid-cols-2 gap-2 text-center">
            <div className="rounded-lg border border-rose-400/15 bg-rose-400/[0.04] px-4 py-3"><p className="font-mono text-xl text-rose-200">{immediateCount}</p><p className="mt-1 text-xs text-muted-foreground">즉시 조치</p></div>
            <div className="rounded-lg border border-amber-400/15 bg-amber-400/[0.04] px-4 py-3"><p className="font-mono text-xl text-amber-200">{verifyCount}</p><p className="mt-1 text-xs text-muted-foreground">확인 필요</p></div>
          </div>
        </div>
        {response.autonomyLegend && Object.keys(response.autonomyLegend).length > 0 && <div className="mt-4 flex flex-wrap items-center gap-x-5 gap-y-2 border-t border-white/8 pt-4">
          <span className="text-xs text-muted-foreground">자율성 레벨</span>
          {Object.entries(response.autonomyLegend).sort(([a], [b]) => a.localeCompare(b)).map(([level, label]) => <span key={level} className="inline-flex items-center gap-2">
            <Badge variant="outline" className={autonomyStyle[level] ?? "border-white/10 text-slate-300"}>{level}</Badge>
            <span className={`text-xs ${autonomyTextStyle[level] ?? "text-slate-300"}`}>{label}</span>
          </span>)}
        </div>}
        {(response.mappingNote || response.analystNote) && <div className="mt-4 border-t border-white/8 pt-4 text-xs leading-5 text-slate-400">{[response.mappingNote, response.analystNote].filter(Boolean).join(" · ")}</div>}
      </section>

      {actions.length ? <div className="space-y-4">
        {actions.map((action, index) => {
          const techniqueUrl = action.techniqueId ? attackUrl(action.techniqueId) : null;
          return (
            <article key={action.id} className="signal-card overflow-hidden">
              <div className="border-b border-white/8 p-5">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="grid size-7 place-items-center rounded-md bg-white/[0.05] font-mono text-xs text-slate-300">{index + 1}</span>
                  <Badge variant="outline" className={action.category === "immediate" ? "border-rose-400/25 bg-rose-400/7 text-rose-200" : "border-amber-400/25 bg-amber-400/7 text-amber-200"}>{action.categoryLabel}</Badge>
                  {action.priority > 0 && <Badge variant="outline" className="border-white/10 text-slate-300">우선순위 {action.priority}</Badge>}
                  {action.risk && <Badge variant="outline" className={riskStyle[action.risk] ?? severityStyle.UNKNOWN}>조치 위험 · {riskLabel[action.risk] ?? action.risk}</Badge>}
                  {action.autonomy && <Badge variant="outline" className={autonomyStyle[action.autonomy] ?? "border-white/10 text-slate-300"}>{action.autonomy}</Badge>}
                  {action.requiresApproval && <span className="text-xs text-violet-300">승인 필요</span>}
                </div>
                <h4 className="mt-3 text-base font-semibold text-slate-100">{action.title}</h4>
                {action.reason && <p className="mt-2 text-sm leading-6 text-muted-foreground">{action.reason}</p>}
              </div>

              <div className="grid gap-px bg-white/8 sm:grid-cols-2">
                <div className="bg-[#091119] p-4"><p className="text-xs text-muted-foreground">대상</p><p className={`mt-2 break-all text-sm leading-6 ${action.target ? "font-mono text-xs text-slate-200" : "text-slate-500"}`}>{action.target || "별도 대상이 지정되지 않았습니다."}</p></div>
                <div className="bg-[#091119] p-4"><p className="text-xs text-muted-foreground">ATT&CK 연결</p>{action.techniqueId ? <p className="mt-2 text-sm text-slate-200">{techniqueUrl ? <a href={techniqueUrl} target="_blank" rel="noreferrer" className="font-mono text-cyan-300 underline decoration-cyan-400/30 underline-offset-4">{action.techniqueId}</a> : <span className="font-mono text-cyan-300">{action.techniqueId}</span>} {action.techniqueName}{action.tacticName ? ` · ${action.tacticName}` : ""}</p> : <p className="mt-2 text-sm leading-6 text-slate-500">일반 권고로 특정 ATT&CK 기법에 연결되지 않았습니다.</p>}</div>
                <div className="bg-[#091119] p-4"><p className="text-xs text-muted-foreground">예상 영향</p><p className={`mt-2 text-sm leading-6 ${action.sideEffects ? "text-slate-300" : "text-slate-500"}`}>{action.sideEffects || "예상 영향이 별도로 기록되지 않았습니다."}</p></div>
                <div className="bg-[#091119] p-4"><p className="flex items-center gap-1.5 text-xs text-muted-foreground"><RotateCcw aria-hidden="true" className="size-3.5" />원복</p><p className={`mt-2 text-sm leading-6 ${action.rollback ? "text-slate-300" : "text-slate-500"}`}>{action.rollback || "원복 절차가 별도로 기록되지 않았습니다."}</p></div>
                <div className="bg-[#091119] p-4"><p className="flex items-center gap-1.5 text-xs text-muted-foreground"><ShieldCheck aria-hidden="true" className="size-3.5" />검증</p><p className={`mt-2 text-sm leading-6 ${action.verification ? "text-slate-300" : "text-slate-500"}`}>{action.verification || "검증 방법이 별도로 기록되지 않았습니다."}</p></div>
                <div className="bg-[#091119] p-4"><p className="flex items-center gap-1.5 text-xs text-muted-foreground"><Waypoints aria-hidden="true" className="size-3.5" />자율성 근거{action.autonomyDowngradedFrom ? ` · ${action.autonomyDowngradedFrom}에서 하향` : ""}</p><p className={`mt-2 text-sm leading-6 ${action.autonomyReason ? "text-slate-300" : "text-slate-500"}`}>{action.autonomyReason || "자율성 근거가 별도로 기록되지 않았습니다."}</p></div>
              </div>

              {(action.commandHint || action.evidenceIds.length > 0) && <div className="space-y-3 border-t border-white/8 p-4">
                {action.commandHint && <div><p className="text-xs text-muted-foreground">명령 참고</p><pre className="mt-2 overflow-x-auto rounded-lg border border-white/8 bg-black/25 p-3 text-xs leading-5 text-cyan-100"><code>{action.commandHint}</code></pre></div>}
                {action.evidenceIds.length > 0 && <div className="flex flex-wrap items-center gap-2"><span className="text-xs text-muted-foreground">근거</span>{action.evidenceIds.map((id) => <code key={id} className="rounded bg-white/5 px-2 py-1 text-xs text-slate-300">{id}</code>)}</div>}
              </div>}
            </article>
          );
        })}
      </div> : <section className="signal-card p-6 text-sm text-muted-foreground">대응 결과는 연결되었지만 표시할 권고 조치가 없습니다.</section>}

      {(response.remainingUnknowns.length > 0 || response.warnings.length > 0 || response.errors.length > 0) && <section className="rounded-xl border border-amber-400/20 bg-amber-400/5 p-5">
        <div className="flex items-center gap-2 text-amber-300"><AlertTriangle aria-hidden="true" className="size-4"/><h3 className="text-sm font-semibold">대응 전 확인 사항</h3></div>
        <ul className="mt-3 space-y-2 text-sm leading-6 text-amber-100/75">{[...response.remainingUnknowns, ...response.warnings, ...response.errors].map((item, index) => <li key={`${index}-${item}`}>• {item}</li>)}</ul>
      </section>}
    </div>
  );
}

function IncidentDetail({ incident, open, onOpenChange, timezone /* , onOpenResponses */ }: {
  incident: Incident | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  timezone: Timezone;
  // onOpenResponses: (incidentId: string) => void;
}) {
  if (!incident) return null;
  const allEvidence = [...incident.evidence, ...incident.contradictingEvidence].sort((a, b) => a.sequence - b.sequence);
  const timeline = incident.timeline.length ? incident.timeline : allEvidence.map((item) => ({ time: item.time, event: item.description, source: item.layer }));
  const layers = [...new Set(allEvidence.map((item) => item.layer))];

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="incident-dialog">
        <DialogHeader className="border-b border-white/8 bg-[#0b121c] px-6 py-5 pr-14 text-left">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={incident.severity} />
            <VerdictLabel verdict={incident.verdict} />
            <ProvenanceBadge status={incident.provenance.status} />
          </div>
          <DialogTitle className="mt-3 text-xl leading-7 text-slate-100">{incident.title}</DialogTitle>
          <DialogDescription className="font-mono text-xs">{incident.incidentId} · {incident.host} · {formatDate(incident.triggerTime, timezone)} {timezone}</DialogDescription>
        </DialogHeader>

        <Tabs defaultValue="summary" className="min-h-0 flex-1 gap-0">
          <TabsList variant="line" className="incident-tabs-list w-full justify-start overflow-x-auto border-b border-white/8 bg-[#0b121c] px-5 py-2">
            <TabsTrigger value="summary" className="flex-none px-4">판정 요약</TabsTrigger>
            <TabsTrigger value="evidence" className="flex-none px-4">타임라인·증거</TabsTrigger>
            <TabsTrigger value="attack" className="flex-none px-4">ATT&CK</TabsTrigger>
            <TabsTrigger value="response" className="flex-none px-4">대응</TabsTrigger>
            <TabsTrigger value="diagnostics" className="flex-none px-4">조사 범위</TabsTrigger>
          </TabsList>

          <div className="min-h-0 flex-1 overflow-y-auto p-5 sm:p-6">
            <TabsContent value="summary" className="space-y-5">
              <section className="grid gap-4 lg:grid-cols-[1.5fr_0.8fr]">
                <article className="signal-card p-5">
                  <p className="text-xs font-semibold uppercase tracking-[0.14em] text-cyan-300">최종 판정 요약</p>
                  <p className="mt-4 text-base leading-7 text-slate-200">{incident.summary}</p>
                  <div className="mt-5 border-t border-white/8 pt-5">
                    <p className="text-sm font-semibold">판정 근거</p>
                    <p className="mt-2 text-sm leading-7 text-muted-foreground">{incident.reasoning}</p>
                  </div>
                </article>
                <article className="signal-card p-5">
                  <p className="text-sm font-semibold">조사 신호</p>
                  <div className="mt-5 space-y-4">
                    <div><div className="flex justify-between text-xs"><span className="text-muted-foreground">판정 확신도 · LLM</span><span className="font-mono text-slate-200">{percent(incident.verdictConfidence)}</span></div><div role="progressbar" aria-label="판정 확신도" aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(incident.verdictConfidence * 100)} className="mt-2 h-1.5 rounded-full bg-white/6"><div className="h-full rounded-full bg-violet-400" style={{ width: percent(incident.verdictConfidence) }} /></div></div>
                    <div><div className="flex justify-between text-xs"><span className="text-muted-foreground">증거 누적 점수</span><span className="font-mono text-slate-200">{percent(incident.investigationConfidence)}</span></div><div role="progressbar" aria-label="증거 누적 점수" aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(incident.investigationConfidence * 100)} className="mt-2 h-1.5 rounded-full bg-white/6"><div className="h-full rounded-full bg-cyan-400" style={{ width: percent(incident.investigationConfidence) }} /></div></div>
                  </div>
                  <div className="mt-6 grid grid-cols-2 gap-3">
                    <div className="rounded-lg border border-white/8 bg-white/[0.02] p-3"><p className="text-xs text-muted-foreground">지지 증거</p><p className="mt-2 font-mono text-xl">{incident.evidence.length}</p></div>
                    <div className="rounded-lg border border-white/8 bg-white/[0.02] p-3"><p className="text-xs text-muted-foreground">반박 증거</p><p className="mt-2 font-mono text-xl">{incident.contradictingEvidence.length}</p></div>
                  </div>
                </article>
              </section>

              <TriageCard incident={incident} timezone={timezone} />

              <section className="grid gap-4 md:grid-cols-3">
                {[
                  ["대상 시스템", incident.affectedSystems.length ? incident.affectedSystems.join(", ") : incident.host],
                  ["관련 출발지", incident.srcIp],
                  ["초기 탐지", incident.triggerDescription],
                ].map(([label, value]) => <div key={label} className="signal-card p-4"><p className="text-xs text-muted-foreground">{label}</p><p className="mt-2 break-words text-sm text-slate-200">{value}</p></div>)}
              </section>

              <section className="signal-card p-5">
                <div className="flex items-center gap-2"><Fingerprint className="size-4 text-emerald-300"/><h3 className="text-sm font-semibold">근거 추적성</h3></div>
                <div className="mt-4 grid gap-3 sm:grid-cols-3">
                  <div><p className="text-xs text-muted-foreground">검증 상태</p><div className="mt-2"><ProvenanceBadge status={incident.provenance.status}/></div></div>
                  <div><p className="text-xs text-muted-foreground">관측 원본 참조</p><p className="mt-2 font-mono text-sm">{incident.provenance.rawRefCount}줄</p></div>
                  <div><p className="text-xs text-muted-foreground">참조 없는 증거</p><p className="mt-2 font-mono text-sm">{incident.provenance.evidenceWithoutRawRefs.length}건</p></div>
                </div>
                <p className="mt-4 text-xs leading-5 text-muted-foreground">근거 검증은 인용한 원본을 역추적할 수 있다는 뜻이며, 공격 판정의 정확성을 보증하지 않습니다.</p>
              </section>

              {incident.unknowns.length > 0 && <section className="rounded-xl border border-amber-400/20 bg-amber-400/5 p-5"><div className="flex items-center gap-2 text-amber-300"><AlertTriangle className="size-4"/><h3 className="text-sm font-semibold">미해결 항목</h3></div><ul className="mt-3 space-y-2 text-sm text-amber-100/75">{incident.unknowns.map((item) => <li key={item}>• {item}</li>)}</ul></section>}
            </TabsContent>

            <TabsContent value="evidence" className="space-y-5">
              <IncidentGraph key={`${incident.sourceFile}-${incident.investigationId}-${timezone}`} incident={incident} timezone={timezone} />
              <div className="grid gap-5 xl:grid-cols-[0.8fr_1.2fr]">
              <section className="signal-card p-5">
                <div className="flex items-center gap-2"><Clock3 className="size-4 text-cyan-300"/><h3 className="text-sm font-semibold">공격 타임라인</h3></div>
                <div className="relative mt-6 space-y-6 before:absolute before:bottom-2 before:left-[5px] before:top-2 before:w-px before:bg-white/10">
                  {timeline.map((item, index) => <div key={`${item.time}-${index}`} className="relative pl-7"><span className="absolute left-0 top-1 size-3 rounded-full border-2 border-cyan-400 bg-[#0a111b]"/><p className="font-mono text-xs text-cyan-300">{formatDate(item.time, timezone)}</p><p className="mt-1 text-sm leading-6 text-slate-200">{item.event}</p>{item.source && <p className="mt-1 text-xs text-muted-foreground">{item.source}</p>}</div>)}
                </div>
              </section>

              <section className="signal-card overflow-hidden">
                <div className="border-b border-white/8 p-5"><div className="flex items-center gap-2"><FileCode2 className="size-4 text-violet-300"/><h3 className="text-sm font-semibold">증거 체인</h3></div><p className="mt-1 text-xs text-muted-foreground">설명은 조사 결과 요약이며, 원본 참조만 표시합니다.</p></div>
                <div className="divide-y divide-white/7">
                  {allEvidence.map((item) => <div key={`${item.id}-${item.sequence}`} className="p-5">
                    <div className="flex flex-wrap items-center gap-2"><span className="font-mono text-xs text-cyan-300">E{item.sequence}</span><Badge variant="outline" className="border-white/10 text-slate-300">{item.layer}</Badge><Badge variant="outline" className={item.stance === "supporting" ? "border-emerald-400/20 text-emerald-300" : "border-amber-400/20 text-amber-300"}>{item.stance === "supporting" ? "지지" : "반박"}</Badge><EvidenceMappingBadge mapping={evidenceMappingOf(item)} /><span className="ml-auto font-mono text-xs text-muted-foreground">{formatDate(item.time, timezone)}</span></div>
                    <p className="mt-3 text-sm leading-6 text-slate-200">{item.description}</p>
                    <details className="mt-3 rounded-lg border border-white/8 bg-black/15 px-3 py-2"><summary className="cursor-pointer text-xs text-muted-foreground">원본 참조 {item.rawRefs.length}개</summary><div className="mt-2 flex flex-wrap gap-2">{item.rawRefs.length ? item.rawRefs.map((ref) => <code key={ref} className="rounded bg-white/5 px-2 py-1 text-xs text-cyan-200">{ref}</code>) : <span className="text-xs text-amber-300">참조 없음</span>}</div></details>
                  </div>)}
                </div>
              </section>
              </div>
            </TabsContent>

            <TabsContent value="attack" className="space-y-5">
              <AttackMappingPanel incident={incident} timezone={timezone} />
            </TabsContent>

            <TabsContent value="response" className="space-y-5">
              {/* 대응 조치 탭 재활성화 시 이동 버튼도 복원합니다.
              <button type="button" onClick={() => onOpenResponses(incident.incidentId)} className="inline-flex items-center gap-2 rounded-lg border border-cyan-400/25 bg-cyan-400/7 px-4 py-2.5 text-sm text-cyan-200"><ShieldCheck className="size-4"/>이 사건의 대응 모아 보기<ArrowRight className="size-4"/></button>
              */}
              <ResponsePanel incident={incident} />
            </TabsContent>

            <TabsContent value="diagnostics" className="space-y-5">
              <section className="signal-card p-5">
                <div className="flex flex-wrap items-center justify-between gap-3"><div><h3 className="text-sm font-semibold">조사 범위</h3><p className="mt-1 text-xs text-muted-foreground">도구 원문 대신 확인한 계층과 결과 건수를 요약합니다.</p></div><span className="font-mono text-xs text-muted-foreground">호출 {incident.statistics.toolCalls}회</span></div>
                <div className="mt-5 flex flex-wrap gap-2">{layers.map((layer) => <Badge key={layer} variant="outline" className="border-cyan-400/20 bg-cyan-400/5 text-cyan-200">{layer}</Badge>)}</div>
              </section>
              <section className="signal-card overflow-hidden">
                <div className="border-b border-white/8 p-5"><h3 className="text-sm font-semibold">도구 실행 요약</h3></div>
                <div className="divide-y divide-white/7">{incident.tools.map((tool) => <details key={`${tool.sequence}-${tool.name}`} className="group p-5"><summary className="flex cursor-pointer list-none items-center gap-3"><span className={`size-2 rounded-full ${tool.success ? "bg-emerald-400" : "bg-rose-400"}`}/><span className="font-mono text-sm text-cyan-200">{tool.name}</span><span className="text-xs text-muted-foreground">결과 {tool.resultCount}건</span><ChevronRight className="ml-auto size-4 text-slate-500 transition group-open:rotate-90"/></summary><p className="mt-3 pl-5 text-sm leading-6 text-muted-foreground">{tool.summary}</p></details>)}</div>
              </section>
            </TabsContent>
          </div>
        </Tabs>
      </DialogContent>
    </Dialog>
  );
}

function Operations({ incidents }: { incidents: Incident[] }) {
  const totalCalls = incidents.reduce((sum, item) => sum + item.statistics.toolCalls, 0);
  const incomplete = incidents.filter((item) => item.provenance.status !== "passed").length;
  const callData = incidents.slice().reverse().map((item) => ({ name: item.incidentId.replace("INC-", ""), calls: item.statistics.toolCalls, evidence: item.statistics.evidenceCount }));
  const callMax = Math.max(1, ...callData.flatMap((item) => [item.calls, item.evidence]));

  return (
    <div className="space-y-5">
      <section className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {[
          ["조사 실행", `${incidents.length}건`, "완료 결과", Activity],
          ["도구 호출", `${totalCalls}회`, `평균 ${(totalCalls / Math.max(incidents.length, 1)).toFixed(1)}회`, Wrench],
          ["근거 경고", `${incomplete}건`, "추적성 확인", Fingerprint],
          ["LLM 계측", "미연결", "토큰·지연시간", BrainCircuit],
        ].map(([label, value, note, Icon]) => {
          const IconComponent = Icon as typeof Activity;
          return <article key={String(label)} className="signal-card p-5"><div className="flex items-center justify-between"><p className="text-sm text-muted-foreground">{String(label)}</p><IconComponent className="size-4 text-cyan-300"/></div><p className="mt-5 font-mono text-2xl font-semibold">{String(value)}</p><p className="mt-2 text-xs text-muted-foreground">{String(note)}</p></article>;
        })}
      </section>

      <section className="grid gap-5 xl:grid-cols-2">
        <article className="signal-card p-5 sm:p-6">
          <PanelTitle icon={BrainCircuit} title="시간대별 LLM 토큰" description="입력·출력·캐시 토큰 계측 슬롯" />
          <div className="mt-6"><EmptyMetric label="토큰 사용량 데이터 없음" /></div>
        </article>
        <article className="signal-card p-5 sm:p-6">
          <PanelTitle icon={TimerReset} title="단계별 실행 시간" description="트리아지·조사·후속 단계 지연시간 슬롯" />
          <div className="mt-6"><EmptyMetric label="실행 시간 데이터 없음" /></div>
        </article>
      </section>

      <section className="grid gap-5 xl:grid-cols-[1.25fr_0.75fr]">
        <article className="signal-card p-5 sm:p-6">
          <PanelTitle icon={BarChart3} title="사건별 조사량" description="현재 결과 JSON에서 확인 가능한 실제 통계" />
          <div className="chart-grid mt-6 flex h-72 items-end gap-3 overflow-x-auto border-b border-white/10 px-2 pt-5">
            {callData.map((item) => (
              <div key={item.name} className="flex h-full min-w-14 flex-1 flex-col justify-end">
                <div className="flex h-[13rem] items-end justify-center gap-1.5" title={`${item.name} · 도구 ${item.calls}, 증거 ${item.evidence}`}>
                  <span className="w-3 rounded-t bg-cyan-400/90" style={{ height: `${Math.max(item.calls ? 7 : 0, (item.calls / callMax) * 100)}%` }} />
                  <span className="w-3 rounded-t bg-violet-400/85" style={{ height: `${Math.max(item.evidence ? 7 : 0, (item.evidence / callMax) * 100)}%` }} />
                </div>
                <p className="mt-3 truncate text-center font-mono text-[0.65rem] text-slate-500">{item.name}</p>
              </div>
            ))}
          </div>
          <div className="mt-4 flex gap-4 text-xs text-muted-foreground"><span className="flex items-center gap-2"><i className="size-2 rounded-full bg-cyan-400"/>도구 호출</span><span className="flex items-center gap-2"><i className="size-2 rounded-full bg-violet-400"/>증거</span></div>
        </article>
        <article className="signal-card p-5 sm:p-6">
          <PanelTitle icon={Database} title="계측 계약" description="운영 상태 활성화에 필요한 입력" />
          <div className="mt-6 space-y-3">
            {["run_id · incident_id · stage", "provider · model · operation", "input/output/cache tokens", "started_at · duration_ms", "retry_count · status · error_type"].map((item, index) => <div key={item} className="flex items-center gap-3 rounded-lg border border-white/8 bg-white/[0.02] p-3"><span className="grid size-6 place-items-center rounded-md bg-cyan-400/8 font-mono text-xs text-cyan-300">{index + 1}</span><code className="text-xs text-slate-300">{item}</code></div>)}
          </div>
        </article>
      </section>
    </div>
  );
}

const pipelineSteps = [
  { step: "01", title: "수집·정규화", subtitle: "Apache · Auth · Audit · Suricata", status: "active", icon: Database },
  { step: "02", title: "탐지", subtitle: "Sigma · 이상탐지", status: "active", icon: Shield },
  { step: "03", title: "사건 묶기", subtitle: "상관관계 연결", status: "active", icon: Layers3 },
  { step: "04", title: "트리아지", subtitle: "조사 가치 · 우선순위", status: "active", icon: Bot },
  { step: "05", title: "조사 에이전트", subtitle: "도구 선택 루프", status: "active", icon: BrainCircuit },
  { step: "06", title: "판정·근거 검증", subtitle: "결론 · 신뢰도 · 출처", status: "active", icon: Fingerprint },
  { step: "07", title: "ATT&CK 매핑", subtitle: "RAG · ID 검증", status: "active", icon: Network },
  { step: "08", title: "대응 생성", subtitle: "근거 기반 조치", status: "active", icon: Sparkles },
  { step: "09", title: "자율성 레벨", subtitle: "권고별 L0 · L1 · L2", status: "active", icon: Waypoints },
  { step: "10", title: "대시보드", subtitle: "판정 · 근거 · 운영", status: "frame", icon: LayoutDashboard },
];

function Pipeline() {
  return (
    <div className="space-y-5">
      <section className="signal-card p-5 sm:p-6">
        <PanelTitle icon={GitBranch} title="SSOC 파이프라인 스냅샷" description="현재 구현 상태와 후속 단계 연결 위치" trailing={<Badge variant="outline" className="border-cyan-400/20 text-cyan-300">데모 파이프라인</Badge>} />
        <div className="mt-8 grid gap-3 lg:grid-cols-5">
          {pipelineSteps.map((item, index) => {
            const Icon = item.icon;
            return <div key={item.step} className="relative">
              <div className={`h-full min-h-36 rounded-xl border p-4 ${item.status === "active" ? "border-emerald-400/20 bg-emerald-400/[0.035]" : item.status === "frame" ? "border-cyan-400/30 bg-cyan-400/[0.06]" : "border-dashed border-slate-600/35 bg-black/10"}`}>
                <div className="flex items-center justify-between"><span className="font-mono text-xs text-slate-400">단계 {item.step}</span><span className={`size-2 rounded-full ${item.status === "active" ? "bg-emerald-400" : item.status === "frame" ? "bg-cyan-400" : "border border-slate-500"}`}/></div>
                <Icon className={`mt-5 size-5 ${item.status === "active" ? "text-emerald-300" : item.status === "frame" ? "text-cyan-300" : "text-slate-500"}`}/>
                <h3 className="mt-3 text-sm font-semibold">{item.title}</h3><p className="mt-1 text-xs leading-5 text-muted-foreground">{item.subtitle}</p>
              </div>
              {index < pipelineSteps.length - 1 && index % 5 !== 4 && <ArrowRight className="absolute -right-[0.68rem] top-1/2 z-10 hidden size-4 -translate-y-1/2 text-slate-500 lg:block"/>}
            </div>;
          })}
        </div>
        <div className="mt-5 flex flex-wrap gap-4 text-xs text-muted-foreground"><span className="flex items-center gap-2"><i className="size-2 rounded-full bg-emerald-400"/>구현·연결됨</span><span className="flex items-center gap-2"><i className="size-2 rounded-full bg-cyan-400"/>현재 대시보드 틀</span><span className="flex items-center gap-2"><i className="size-2 rounded-full border border-slate-500"/>후속 산출물 대기</span></div>
      </section>

      <section className="grid gap-5 xl:grid-cols-[0.85fr_1.15fr]">
        <article className="signal-card p-5 sm:p-6">
          <PanelTitle icon={Server} title="모델 연결" description="코드 구성 기준 스냅샷" />
          <div className="mt-6 space-y-3">
            <div className="rounded-xl border border-cyan-400/20 bg-cyan-400/[0.04] p-4"><div className="flex items-center justify-between"><div><p className="text-xs text-muted-foreground">기본 제공자</p><p className="mt-2 font-medium">Anthropic Claude</p></div><Badge variant="outline" className="border-cyan-400/20 text-cyan-300">기본값</Badge></div><p className="mt-3 font-mono text-xs text-slate-300">claude-sonnet-5 · 거절 시 claude-sonnet-4-6</p><p className="mt-2 text-xs text-muted-foreground">조사 에이전트와 ATT&CK 매핑 선택 단계가 같은 모델을 씁니다. 트리아지 1차 의견은 claude-haiku-4-5입니다.</p></div>
            <div className="rounded-xl border border-white/8 bg-white/[0.02] p-4"><p className="text-xs text-muted-foreground">지원 제공자</p><p className="mt-2 font-medium">Google Gemini</p><p className="mt-3 text-xs text-muted-foreground">LLM_PROVIDER=gemini 로 교체 가능</p></div>
            <div className="rounded-lg border border-amber-400/15 bg-amber-400/5 p-3 text-xs leading-5 text-amber-100/65">조사 결과 JSON에는 실제 실행 모델 ID가 기록되지 않아, 결과별 사용 모델은 확인할 수 없습니다.</div>
          </div>
        </article>

        <article className="signal-card p-5 sm:p-6">
          <PanelTitle icon={TerminalSquare} title="프롬프트 역할 요약" description="전문은 노출하지 않고 목적과 안전 제약만 표시합니다." />
          <div className="mt-6 grid gap-4 md:grid-cols-2">
            <div className="rounded-xl border border-white/8 bg-white/[0.02] p-4"><div className="flex items-center gap-2 text-cyan-300"><Bot className="size-4"/><h3 className="text-sm font-semibold">트리아지</h3></div><p className="mt-3 text-sm leading-6 text-muted-foreground">조사할 가치가 있는 후보와 상대적 우선순위를 선택합니다.</p><ul className="mt-4 space-y-2 text-xs text-slate-300"><li>• 입력 로그 밖의 사건 생성 금지</li><li>• 원본 참조 인용 필수</li><li>• 후보 0개 허용</li></ul></div>
            <div className="rounded-xl border border-white/8 bg-white/[0.02] p-4"><div className="flex items-center gap-2 text-violet-300"><BrainCircuit className="size-4"/><h3 className="text-sm font-semibold">조사 에이전트</h3></div><p className="mt-3 text-sm leading-6 text-muted-foreground">가설을 세우고 필요한 로그 계층을 선택해 증거를 확장합니다.</p><ul className="mt-4 space-y-2 text-xs text-slate-300"><li>• 관측된 근거만 인용</li><li>• 지지·반박 증거 분리</li><li>• 종료 조건 코드 검증</li></ul></div>
          </div>
          <div className="mt-4 rounded-lg border border-white/8 p-4"><div className="flex items-center gap-2"><FileCode2 className="size-4 text-slate-400"/><p className="text-sm font-medium">노출하지 않는 항목</p></div><p className="mt-2 text-xs leading-5 text-muted-foreground">시스템 프롬프트 전문, 실행 중 사용자 프롬프트, 원본 로그 페이로드, 내부 오류 복구 지시, 자격 증명</p></div>
        </article>
      </section>
    </div>
  );
}

export default function Home() {
  const [dashboardData, setDashboardData] = useState<DashboardData>(resultData);
  const [view, setView] = useState<View>("overview");
  // const [responseIncidentFilter, setResponseIncidentFilter] = useState<string | null>(null);
  const [selectedIncidentKey, setSelectedIncidentKey] = useState<string | null>(null);
  const [detailOpen, setDetailOpen] = useState(false);
  const [timezone, setTimezone] = useState<Timezone>("UTC");
  const [syncStatus, setSyncStatus] = useState<SyncStatus>("connecting");
  const [refreshing, setRefreshing] = useState(false);
  const [newIncidentCount, setNewIncidentCount] = useState(0);
  const [announcement, setAnnouncement] = useState("");
  const [incidentFilterPreset, setIncidentFilterPreset] = useState<IncidentFilterPreset>({ revision: 0, verdict: "ALL", severity: "ALL" });
  const [incidentViewPreset, setIncidentViewPreset] = useState<IncidentViewPreset>({ revision: 0, tab: "results", detectionState: "ALL" });
  const dashboardDataRef = useRef<DashboardData>(resultData);
  const requestRef = useRef<AbortController | null>(null);
  const requestRunningRef = useRef(false);
  const incidents = dashboardData.incidents;
  const pipeline = pipelineOf(dashboardData);
  const active = navigation.find((item) => item.id === view) ?? navigation[0];
  const confirmedThreats = incidents.filter((item) => item.verdict === "THREAT_CONFIRMED").length;
  const selectedIncident = selectedIncidentKey
    ? incidents.find((item) => `${item.sourceFile}::${item.investigationId}` === selectedIncidentKey) ?? null
    : null;

  const refreshData = useCallback(async () => {
    if (requestRunningRef.current) return;
    requestRunningRef.current = true;
    setRefreshing(true);
    const controller = new AbortController();
    requestRef.current = controller;

    try {
      const response = await fetch(`/data/incidents.generated.json?v=${Date.now()}`, {
        cache: "no-store",
        headers: { Accept: "application/json" },
        signal: controller.signal,
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const nextData: unknown = await response.json();
      if (!isDashboardData(nextData)) throw new Error("대시보드 데이터 형식이 올바르지 않습니다.");

      const currentData = dashboardDataRef.current;
      if (nextData.generatedAt !== currentData.generatedAt) {
        const existingKeys = new Set(currentData.incidents.map((item) => `${item.sourceFile}::${item.investigationId}`));
        const addedCount = nextData.incidents.filter((item) => !existingKeys.has(`${item.sourceFile}::${item.investigationId}`)).length;
        dashboardDataRef.current = nextData;
        setDashboardData(nextData);
        if (addedCount > 0) {
          setNewIncidentCount((count) => count + addedCount);
          setAnnouncement(`새 조사 결과 ${addedCount}건이 도착했습니다.`);
        }
      }
      setSyncStatus("live");
    } catch (error) {
      if (!(error instanceof DOMException && error.name === "AbortError")) setSyncStatus("retrying");
    } finally {
      if (requestRef.current === controller) requestRef.current = null;
      requestRunningRef.current = false;
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    const initialTimer = window.setTimeout(() => void refreshData(), 0);
    const timer = window.setInterval(() => void refreshData(), 1_250);
    const onVisibilityChange = () => {
      if (document.visibilityState === "visible") void refreshData();
    };
    document.addEventListener("visibilitychange", onVisibilityChange);
    return () => {
      window.clearTimeout(initialTimer);
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", onVisibilityChange);
      requestRef.current?.abort();
    };
  }, [refreshData]);

  const openIncident = (incident: Incident) => {
    setSelectedIncidentKey(`${incident.sourceFile}::${incident.investigationId}`);
    setDetailOpen(true);
  };

  // 탐지·대기열 표의 "열기" — 조사 결과 키(sourceFile::investigationId)로 같은 상세 창을 엽니다.
  const openIncidentByKey = (resultKey: string) => {
    setSelectedIncidentKey(resultKey);
    setDetailOpen(true);
  };

  const changeView = (nextView: View) => {
    // if (nextView === "responses") setResponseIncidentFilter(null);
    if (nextView === "incidents") setIncidentViewPreset((current) => ({ revision: current.revision + 1, tab: "results", detectionState: "ALL" }));
    if (view === "incidents" && nextView !== "incidents") {
      setIncidentFilterPreset((current) => ({
        revision: current.revision + 1,
        verdict: "ALL",
        severity: "ALL",
      }));
    }
    setView(nextView);
    if (nextView === "incidents") setNewIncidentCount(0);
  };

  const openFilteredIncidents = (filter: Pick<IncidentFilterPreset, "verdict" | "severity">) => {
    setIncidentFilterPreset((current) => ({ ...filter, revision: current.revision + 1 }));
    setIncidentViewPreset((current) => ({ revision: current.revision + 1, tab: "results", detectionState: "ALL" }));
    setView("incidents");
    setNewIncidentCount(0);
    setAnnouncement("선택한 조건으로 사건 목록을 열었습니다.");
  };

  const openDetectionQueue = () => {
    setIncidentViewPreset((current) => ({ revision: current.revision + 1, tab: "detections", detectionState: "queued" }));
    setView("incidents");
    setNewIncidentCount(0);
    setAnnouncement("조사 대기 상태의 탐지·대기열을 열었습니다.");
  };

  const statusLabel = syncStatus === "live" ? "실시간 연결" : syncStatus === "retrying" ? "재연결 중" : "연결 중";
  const StatusIcon = syncStatus === "retrying" ? WifiOff : Radio;

  return (
    <main className="dashboard-shell min-h-screen bg-background text-foreground">
      <a href="#dashboard-content" className="skip-link">본문으로 바로가기</a>
      <p className="sr-only" aria-live="polite" aria-atomic="true">{announcement}</p>

      <aside className="fixed inset-y-0 left-0 z-20 hidden w-72 border-r border-border bg-sidebar/95 backdrop-blur-xl lg:flex lg:flex-col">
        <div className="flex h-20 items-center gap-3 border-b border-border px-6">
          <img src="/ssoc-logo.png" alt="" aria-hidden="true" className="brand-logo size-12 shrink-0 object-contain" />
          <div><p className="text-xl font-black tracking-[0.16em]">SSOC</p><p className="text-xs text-muted-foreground">Security Operations Center</p></div>
        </div>
        <div className="px-6 pb-2 pt-6 text-[0.7rem] font-semibold uppercase tracking-[0.16em] text-slate-500">관제 작업 공간</div>
        <nav className="space-y-1 px-3" aria-label="주요 메뉴">
          {navigation.map((item) => {
            const Icon = item.icon;
            const isActive = item.id === view;
            return (
              <button
                type="button"
                key={item.id}
                onClick={() => changeView(item.id)}
                aria-current={isActive ? "page" : undefined}
                className={`sidebar-nav-item flex w-full items-center gap-3 rounded-xl px-3 py-3 text-left transition ${isActive ? "is-active text-cyan-100" : "text-muted-foreground hover:bg-white/[0.035] hover:text-foreground"}`}
              >
                <span className={`grid size-9 shrink-0 place-items-center rounded-lg ${isActive ? "bg-cyan-400/12 text-cyan-300" : "bg-white/[0.025]"}`}><Icon aria-hidden="true" className="size-4" /></span>
                <span className="min-w-0 flex-1"><span className="block text-sm font-semibold">{item.label}</span><span className="mt-0.5 block truncate text-xs opacity-70">{item.description}</span></span>
                {item.id === "incidents" && confirmedThreats > 0 && <span className="rounded-full bg-rose-400/12 px-2 py-1 font-mono text-xs text-rose-300">{confirmedThreats}</span>}
              </button>
            );
          })}
        </nav>
        <div className="mt-auto border-t border-border p-4">
          <div className={`rounded-xl border p-4 ${syncStatus === "retrying" ? "border-amber-400/20 bg-amber-400/5" : "border-emerald-400/20 bg-emerald-400/5"}`}>
            <p className={`flex items-center gap-2 text-xs font-semibold ${syncStatus === "retrying" ? "text-amber-300" : "text-emerald-300"}`}><StatusIcon aria-hidden="true" className={`size-3.5 ${syncStatus === "live" ? "live-pulse" : ""}`} />{statusLabel}</p>
            <p className="mt-2 text-xs leading-5 text-muted-foreground">결과 폴더의 새 JSON을 자동으로 반영합니다.</p>
            <p className="mt-2 font-mono text-[0.7rem] text-slate-400">마지막 반영 {formatSyncTime(dashboardData.generatedAt, timezone)}</p>
          </div>
        </div>
      </aside>

      <section className="lg:pl-72">
        <header className="sticky top-0 z-10 border-b border-border bg-background/90 backdrop-blur-xl">
          <div className="mx-auto flex min-h-20 max-w-[1800px] flex-wrap items-center justify-between gap-3 px-4 py-3 sm:px-6 2xl:px-8">
            <div className="flex min-w-0 items-center gap-3">
              <img src="/ssoc-logo.png" alt="" aria-hidden="true" className="brand-logo size-10 shrink-0 object-contain lg:hidden" />
              <div className="min-w-0"><p className="truncate text-xs font-medium text-muted-foreground">{active.description}</p><h1 className="truncate text-xl font-bold tracking-tight sm:text-2xl">{active.label}</h1></div>
            </div>
            <div className="flex items-center gap-2 sm:gap-3">
              {newIncidentCount > 0 && (
                <button type="button" onClick={() => changeView("incidents")} className="new-event-pill inline-flex min-h-10 items-center gap-2 rounded-full border border-cyan-400/30 bg-cyan-400/10 px-3 text-xs font-semibold text-cyan-200">
                  <span className="size-2 rounded-full bg-cyan-300" />신규 {newIncidentCount}건
                </button>
              )}
              <div className={`live-status flex min-h-10 min-w-10 items-center justify-center gap-2 rounded-full border px-2 sm:px-3 ${syncStatus === "retrying" ? "border-amber-400/25 bg-amber-400/5 text-amber-300" : "border-emerald-400/25 bg-emerald-400/5 text-emerald-300"}`} title={`마지막 반영: ${formatSyncTime(dashboardData.generatedAt, timezone)} ${timezone}`} aria-label={`${statusLabel}. 마지막 반영 ${formatSyncTime(dashboardData.generatedAt, timezone)} ${timezone}`}>
                <StatusIcon aria-hidden="true" className={`size-3.5 ${syncStatus === "live" ? "live-pulse" : ""}`} />
                <span className="hidden text-xs font-semibold sm:inline">{statusLabel}</span>
                <span className="hidden border-l border-current/20 pl-2 font-mono text-[0.7rem] opacity-75 xl:inline">{formatSyncTime(dashboardData.generatedAt, timezone)}</span>
              </div>
              <button type="button" onClick={() => void refreshData()} disabled={refreshing} className="grid size-10 place-items-center rounded-xl border border-white/10 bg-black/20 text-muted-foreground transition hover:border-cyan-400/30 hover:text-cyan-200 disabled:cursor-wait" aria-label="지금 새로고침" title="지금 새로고침"><RefreshCw aria-hidden="true" className={`size-4 ${refreshing ? "animate-spin" : ""}`} /></button>
              <div className="flex items-center rounded-xl border border-white/10 bg-black/20 p-1" aria-label="시간대 선택">{(["UTC", "KST"] as const).map((zone) => <button type="button" key={zone} onClick={() => setTimezone(zone)} aria-pressed={timezone === zone} className={`min-h-8 min-w-11 rounded-lg px-2 font-mono text-xs font-semibold transition sm:px-3 ${timezone === zone ? "bg-cyan-300 text-[#041112] shadow-sm" : "text-muted-foreground hover:text-foreground"}`}>{zone}</button>)}</div>
            </div>
          </div>
          <nav className="grid grid-cols-4 border-t border-white/6 px-2 lg:hidden" aria-label="모바일 메뉴">{navigation.map((item) => { const Icon = item.icon; const isActive = view === item.id; return <button type="button" key={item.id} onClick={() => changeView(item.id)} aria-current={isActive ? "page" : undefined} className={`flex min-w-0 flex-col items-center gap-1.5 border-b-2 px-1 py-2.5 text-[0.7rem] font-medium transition sm:flex-row sm:justify-center sm:text-sm ${isActive ? "border-cyan-300 text-cyan-200" : "border-transparent text-muted-foreground"}`}><Icon aria-hidden="true" className="size-4"/><span className="truncate">{item.label}</span></button>; })}</nav>
        </header>

        <div id="dashboard-content" className="mx-auto max-w-[1800px] p-4 pb-10 sm:p-6 2xl:p-8" tabIndex={-1}>
          {view === "overview" && <Overview incidents={incidents} pipeline={pipeline} onOpenIncident={openIncident} onOpenFilteredIncidents={openFilteredIncidents} onOpenDetectionQueue={openDetectionQueue} timezone={timezone} />}
          {view === "incidents" && <IncidentsView key={`incidents-${incidentFilterPreset.revision}-${incidentViewPreset.revision}`} incidents={incidents} pipeline={pipeline} onOpenIncident={openIncident} onOpenResult={openIncidentByKey} filterPreset={incidentFilterPreset} viewPreset={incidentViewPreset} timezone={timezone} />}
          {/* 대응 조치 탭 임시 비활성화
          {view === "responses" && <ResponseCenter key={`responses-${responseIncidentFilter ?? "all"}`} incidents={incidents} incidentId={responseIncidentFilter} timezone={timezone} onOpenIncident={(item) => {
            const incident = incidents.find((candidate) => candidate.sourceFile === item.sourceFile && candidate.investigationId === item.investigationId);
            if (incident) openIncident(incident);
          }} />}
          */}
          {view === "operations" && <Operations incidents={incidents} />}
          {view === "pipeline" && <Pipeline />}
        </div>
      </section>

      <IncidentDetail incident={selectedIncident} open={detailOpen} onOpenChange={setDetailOpen} timezone={timezone}
        /* onOpenResponses={(incidentId) => {
        setResponseIncidentFilter(incidentId);
        setDetailOpen(false);
        setView("responses");
        }} */
      />
    </main>
  );
}
