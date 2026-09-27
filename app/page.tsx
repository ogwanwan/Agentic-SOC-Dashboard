"use client";

import { useEffect, useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  ArrowDown,
  ArrowRight,
  BarChart3,
  Bot,
  BrainCircuit,
  CheckCircle2,
  ChevronRight,
  CircleDashed,
  CircleDot,
  Clock3,
  Database,
  FileCode2,
  Fingerprint,
  GitBranch,
  Layers3,
  LayoutDashboard,
  ListTree,
  Network,
  Search,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  TerminalSquare,
  TimerReset,
  Waypoints,
  Wrench,
  XCircle,
  ZoomIn,
  ZoomOut,
  Maximize2,
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
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select";
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

type Incident = (typeof resultData.incidents)[number];
type View = "overview" | "incidents" | "operations" | "pipeline";
type Timezone = "UTC" | "KST";

const navigation = [
  { id: "overview" as View, label: "Overview", description: "전체 흐름", icon: LayoutDashboard },
  { id: "incidents" as View, label: "사건", description: "조사 결과", icon: ListTree },
  { id: "operations" as View, label: "운영 상태", description: "성능·비용", icon: Activity },
  { id: "pipeline" as View, label: "파이프라인", description: "구성 스냅샷", icon: GitBranch },
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

const verdictMeta: Record<string, { label: string; color: string; icon: typeof Shield }> = {
  THREAT_CONFIRMED: { label: "위협 확인", color: "text-rose-300", icon: ShieldAlert },
  FALSE_POSITIVE: { label: "비위협 판정", color: "text-emerald-300", icon: ShieldCheck },
  INCONCLUSIVE: { label: "결론 불충분", color: "text-amber-300", icon: AlertTriangle },
};

function formatDate(value: string, timezone: Timezone, withDate = true) {
  if (!value) return "-";
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
          <Icon className="size-4" />
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

function Overview({ incidents, onOpenIncident, timezone }: { incidents: Incident[]; onOpenIncident: (item: Incident) => void; timezone: Timezone }) {
  const counts = useMemo(() => ({
    all: incidents.length,
    threat: incidents.filter((item) => item.verdict === "THREAT_CONFIRMED").length,
    benign: incidents.filter((item) => item.verdict === "FALSE_POSITIVE").length,
    inconclusive: incidents.filter((item) => item.verdict === "INCONCLUSIVE").length,
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
  const severityColors: Record<string, string> = { CRITICAL: "#ff5e68", HIGH: "#ff875f", MEDIUM: "#f4b84a", LOW: "#5da9ff", UNKNOWN: "#718792" };

  const attention = useMemo(() => [...incidents]
    .sort((a, b) => {
      const provenanceGap = Number(b.provenance.status !== "passed") - Number(a.provenance.status !== "passed");
      return (severityOrder[a.severity] ?? 9) - (severityOrder[b.severity] ?? 9) || provenanceGap;
    })
    .slice(0, 5), [incidents]);

  const cards = [
    { label: "전체 사건", value: counts.all, note: "조사 결과", color: "text-cyan-300", tone: "all", icon: Layers3 },
    { label: "위협 확인", value: counts.threat, note: "판정 완료", color: "text-rose-300", tone: "threat", icon: ShieldAlert },
    { label: "비위협 판정", value: counts.benign, note: "오탐 포함", color: "text-emerald-300", tone: "benign", icon: ShieldCheck },
    { label: "결론 불충분", value: counts.inconclusive, note: "추가 확인", color: "text-amber-300", tone: "inconclusive", icon: AlertTriangle },
  ];

  return (
    <div className="space-y-5">
      <section className="grid gap-4 sm:grid-cols-2 2xl:grid-cols-4">
        {cards.map((card) => {
          const Icon = card.icon;
          return (
            <article key={card.label} className={`signal-card overview-metric overview-metric--${card.tone} p-5`}>
              <div className="flex items-center justify-between">
                <p className="text-sm text-muted-foreground">{card.label}</p>
                <span className="overview-metric__icon"><Icon className={`size-4 ${card.color}`} /></span>
              </div>
              <div className="mt-5 flex items-end justify-between gap-3">
                <strong className={`font-mono text-3xl font-semibold tracking-tight ${card.color}`}>{card.value}</strong>
                <span className="text-xs text-muted-foreground">{card.note}</span>
              </div>
            </article>
          );
        })}
      </section>

      <section className="grid gap-5 2xl:grid-cols-[1.55fr_0.8fr]">
        <article className="signal-card min-h-[25rem] p-5 sm:p-6">
          <PanelTitle
            icon={BarChart3}
            title="시간대별 판정 추이"
            description="조사 완료 사건을 최초 탐지 시각 기준으로 집계합니다."
            trailing={<span className="font-mono text-xs text-muted-foreground">{timezone}</span>}
          />
          <div className="mt-7 h-72 min-w-0">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={timelineData} margin={{ top: 8, right: 8, left: -24, bottom: 0 }} barCategoryGap="32.5%" accessibilityLayer={false}>
                <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#1b3038" />
                <XAxis dataKey="label" tickLine={false} axisLine={false} tick={{ fill: "#718792", fontSize: 11 }} />
                <YAxis tickLine={false} axisLine={false} allowDecimals={false} tick={{ fill: "#718792", fontSize: 11 }} />
                <Tooltip cursor={false} formatter={(value, name) => [`${value}건`, name]} contentStyle={{ background: "#0c181e", border: "1px solid #213942", borderRadius: 8, fontSize: 12 }} />
                <Bar dataKey="threat" name="위협 확인" fill="#ff5e68" radius={[3, 3, 0, 0]} activeBar={false} />
                <Bar dataKey="benign" name="비위협 판정" fill="#55d58b" radius={[3, 3, 0, 0]} activeBar={false} />
                <Bar dataKey="inconclusive" name="결론 불충분" fill="#f4b84a" radius={[3, 3, 0, 0]} activeBar={false} />
              </BarChart>
            </ResponsiveContainer>
          </div>
          <div className="mt-2 flex flex-wrap gap-4 text-xs text-muted-foreground">
            <span className="flex items-center gap-2"><i className="size-2 rounded-full bg-rose-400" />위협 확인</span>
            <span className="flex items-center gap-2"><i className="size-2 rounded-full bg-emerald-400" />비위협 판정</span>
            <span className="flex items-center gap-2"><i className="size-2 rounded-full bg-amber-400" />결론 불충분</span>
          </div>
        </article>

        <article className="signal-card min-h-[25rem] p-5 sm:p-6">
          <PanelTitle icon={Activity} title="심각도 분포" description="최종 판정의 영향 수준" />
          <div className="mt-5 grid min-h-64 grid-cols-[minmax(0,1fr)_8rem] items-center gap-2">
            <div className="relative h-60 min-w-0">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart accessibilityLayer={false}>
                  <Pie data={severityData} dataKey="value" nameKey="name" innerRadius={66} outerRadius={92} paddingAngle={3} cornerRadius={5} stroke="none">
                    {severityData.map((item) => <Cell key={item.name} fill={severityColors[item.name]} />)}
                  </Pie>
                  <Tooltip formatter={(value, name) => [`${value}건`, name]} contentStyle={{ background: "#0c181e", border: "1px solid #26434d", borderRadius: 8, fontSize: 12 }} />
                </PieChart>
              </ResponsiveContainer>
              <div className="pointer-events-none absolute inset-0 grid place-content-center text-center"><strong className="font-mono text-3xl">{incidents.length}</strong><span className="mt-1 text-xs text-muted-foreground">전체 사건</span></div>
            </div>
            <div className="space-y-3">
              {severityData.map((item) => <div key={item.name} className="flex items-center justify-between gap-2 text-xs"><span className="flex items-center gap-2 font-mono text-slate-400"><i className="size-2 rounded-full" style={{ background: severityColors[item.name] }} />{item.name}</span><strong className="font-mono text-slate-200">{item.value}</strong></div>)}
            </div>
          </div>
          <div className="rounded-lg border border-white/8 bg-white/[0.02] p-3 text-sm text-muted-foreground">
            심각도는 조사 순서인 priority와 분리해 표시합니다.
          </div>
        </article>
      </section>

      <section className="grid gap-5 xl:grid-cols-[1.3fr_0.8fr]">
        <article className="signal-card p-5 sm:p-6">
          <PanelTitle icon={ShieldAlert} title="우선 확인 사건" description="심각도와 근거 상태를 기준으로 정렬했습니다." />
          <div className="mt-5 divide-y divide-white/7">
            {attention.map((incident) => (
              <button key={incident.investigationId} onClick={() => onOpenIncident(incident)} className="group flex w-full items-center gap-4 py-4 text-left">
                <div className={`h-10 w-1 rounded-full ${incident.severity === "CRITICAL" ? "bg-rose-400" : incident.severity === "MEDIUM" ? "bg-amber-400" : "bg-blue-400"}`} />
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <SeverityBadge severity={incident.severity} />
                    <span className="font-mono text-xs text-muted-foreground">{incident.incidentId}</span>
                  </div>
                  <p className="mt-2 truncate text-sm font-medium text-slate-200">{incident.title}</p>
                  <p className="mt-1 truncate text-xs text-muted-foreground">{incident.summary}</p>
                </div>
                <ChevronRight className="size-4 text-slate-600 transition group-hover:translate-x-1 group-hover:text-cyan-300" />
              </button>
            ))}
          </div>
        </article>

        <article className="signal-card p-5 sm:p-6">
          <PanelTitle icon={Waypoints} title="자율성별 처리 현황" description="⑧ 대응 생성·⑨ 자율성 레벨 확장 슬롯" />
          <div className="mt-6 space-y-3">
            {[
              ["L0", "권고만 생성", "사용자 직접 검토"],
              ["L1", "승인 후 실행", "HITL 승인 필요"],
              ["L2", "자동 실행", "정책 범위 내 자동화"],
            ].map(([level, title, note]) => (
              <div key={level} className="flex items-center gap-4 rounded-lg border border-white/8 bg-white/[0.02] p-4">
                <span className="grid size-10 place-items-center rounded-lg border border-violet-400/20 bg-violet-400/8 font-mono text-sm font-bold text-violet-300">{level}</span>
                <div className="min-w-0 flex-1"><p className="text-sm font-medium">{title}</p><p className="mt-1 text-xs text-muted-foreground">{note}</p></div>
                <Badge variant="outline" className="border-slate-600/40 text-slate-400">연결 예정</Badge>
              </div>
            ))}
          </div>
          <p className="mt-4 text-xs leading-5 text-muted-foreground">아직 산출물이 없어 실제 처리 건수는 표시하지 않습니다.</p>
        </article>
      </section>
    </div>
  );
}

function IncidentList({ incidents, onOpenIncident, timezone }: { incidents: Incident[]; onOpenIncident: (item: Incident) => void; timezone: Timezone }) {
  const [query, setQuery] = useState("");
  const [verdict, setVerdict] = useState("ALL");
  const [severity, setSeverity] = useState("ALL");

  const filtered = useMemo(() => incidents.filter((item) => {
    const text = `${item.incidentId} ${item.title} ${item.host} ${item.srcIp} ${item.summary}`.toLowerCase();
    return text.includes(query.toLowerCase()) && (verdict === "ALL" || item.verdict === verdict) && (severity === "ALL" || item.severity === severity);
  }), [incidents, query, severity, verdict]);

  return (
    <section className="signal-card overflow-hidden">
      <div className="border-b border-white/8 p-5 sm:p-6">
        <PanelTitle icon={ListTree} title="사건 목록" description={`${filtered.length}건의 조사 결과`} />
        <div className="mt-5 grid gap-3 md:grid-cols-[minmax(0,1fr)_170px_150px]">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-slate-500" />
            <Input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="사건 ID, IP, 호스트, 공격 유형 검색" className="h-10 border-white/10 bg-black/15 pl-10" />
          </div>
          <NativeSelect value={verdict} onChange={(event) => setVerdict(event.target.value)} className="h-10 w-full border-white/10 bg-black/15">
            <NativeSelectOption value="ALL">모든 판정</NativeSelectOption>
            <NativeSelectOption value="THREAT_CONFIRMED">위협 확인</NativeSelectOption>
            <NativeSelectOption value="FALSE_POSITIVE">비위협 판정</NativeSelectOption>
            <NativeSelectOption value="INCONCLUSIVE">결론 불충분</NativeSelectOption>
          </NativeSelect>
          <NativeSelect value={severity} onChange={(event) => setSeverity(event.target.value)} className="h-10 w-full border-white/10 bg-black/15">
            <NativeSelectOption value="ALL">모든 심각도</NativeSelectOption>
            {Object.keys(severityOrder).map((item) => <NativeSelectOption key={item} value={item}>{item}</NativeSelectOption>)}
          </NativeSelect>
        </div>
      </div>

      <Table>
        <TableHeader>
          <TableRow className="border-white/8 bg-white/[0.025] hover:bg-white/[0.025]">
            <TableHead className="px-5 text-xs text-muted-foreground">사건</TableHead>
            <TableHead className="text-xs text-muted-foreground">심각도</TableHead>
            <TableHead className="text-xs text-muted-foreground">판정</TableHead>
            <TableHead className="text-xs text-muted-foreground">대상 / 출발지</TableHead>
            <TableHead className="text-xs text-muted-foreground">증거</TableHead>
            <TableHead className="text-xs text-muted-foreground">근거 상태</TableHead>
            <TableHead className="pr-5 text-right text-xs text-muted-foreground">탐지 시각</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {filtered.map((incident) => (
            <TableRow key={incident.investigationId} onClick={() => onOpenIncident(incident)} className="cursor-pointer border-white/7 hover:bg-cyan-400/[0.035]">
              <TableCell className="max-w-[26rem] px-5 py-4">
                <p className="font-mono text-xs text-cyan-300">{incident.incidentId}</p>
                <p className="mt-1.5 truncate font-medium text-slate-200">{incident.title}</p>
                <p className="mt-1 max-w-[26rem] truncate text-xs text-muted-foreground">{incident.summary}</p>
              </TableCell>
              <TableCell><SeverityBadge severity={incident.severity} /></TableCell>
              <TableCell><VerdictLabel verdict={incident.verdict} /></TableCell>
              <TableCell>
                <p className="text-sm text-slate-300">{incident.host}</p>
                <p className="mt-1 font-mono text-xs text-muted-foreground">{incident.srcIp}</p>
              </TableCell>
              <TableCell className="font-mono text-xs text-muted-foreground">+{incident.evidence.length} / −{incident.contradictingEvidence.length}</TableCell>
              <TableCell><ProvenanceBadge status={incident.provenance.status} /></TableCell>
              <TableCell className="pr-5 text-right font-mono text-xs text-muted-foreground">{formatDate(incident.triggerTime, timezone)}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      {!filtered.length && <div className="p-12 text-center text-sm text-muted-foreground">조건에 맞는 사건이 없습니다.</div>}
    </section>
  );
}

function IncidentGraph({ incident, timezone }: { incident: Incident; timezone: Timezone }) {
  const [active, setActive] = useState(0);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [dragging, setDragging] = useState(false);
  const [dragOrigin, setDragOrigin] = useState({ x: 0, y: 0 });
  const nodes = useMemo(() => {
    const sourceNodes = incident.srcIp ? [{ id: `source-${incident.srcIp}`, label: "출발지", title: incident.srcIp, detail: incident.detectionSource || "외부 접근 주체", icon: Network, color: "rose" }] : [];
    const eventNodes = incident.timeline.length
      ? incident.timeline.map((item, index) => ({ id: `timeline-${index}-${item.time}`, label: `이벤트 ${index + 1}`, title: item.event, detail: [item.source, formatDate(item.time, timezone)].filter(Boolean).join(" · "), icon: Activity, color: index % 2 ? "cyan" : "amber" }))
      : [...incident.evidence, ...incident.contradictingEvidence]
          .sort((a, b) => a.sequence - b.sequence)
          .map((item) => ({ id: `evidence-${item.id}`, label: item.stance === "supporting" ? "지지 증거" : "반박 증거", title: item.description, detail: `${item.layer} · ${item.eventType}`, icon: Fingerprint, color: item.stance === "supporting" ? "cyan" : "amber" }));
    const systems = incident.affectedSystems.length ? incident.affectedSystems : incident.host ? [incident.host] : [];
    const targetNodes = [...new Set(systems)].map((system) => ({ id: `target-${system}`, label: "영향 시스템", title: system, detail: incident.title, icon: Server, color: "violet" }));
    return [...sourceNodes, ...eventNodes, ...targetNodes];
  }, [incident, timezone]);
  const fitZoom = Math.max(0.55, Math.min(1, 4 / Math.max(nodes.length, 1)));

  useEffect(() => {
    setActive(0);
    setZoom(Math.max(0.55, Math.min(1, 4 / Math.max(nodes.length, 1))));
    setPan({ x: 0, y: 0 });
  }, [incident.investigationId, nodes.length]);

  const changeZoom = (next: number) => setZoom(Math.min(1.6, Math.max(0.5, Number(next.toFixed(2)))));
  const fitGraph = () => {
    setZoom(fitZoom);
    setPan({ x: 0, y: 0 });
  };
  const selected = nodes[active];
  if (!selected) return null;
  const SelectedIcon = selected.icon;
  return <section className="attack-graph signal-card p-5">
    <div className="flex flex-wrap items-center justify-between gap-3"><div><p className="text-xs font-semibold uppercase tracking-[0.14em] text-cyan-300">Attack path graph</p><h3 className="mt-2 font-semibold">사건 연결 관계</h3></div><div className="flex items-center gap-3"><span className="font-mono text-xs text-muted-foreground">Nodes {nodes.length} · Edges {nodes.length - 1}</span><div className="attack-zoom-controls" aria-label="그래프 확대 및 축소"><button type="button" onClick={() => changeZoom(zoom - 0.1)} disabled={zoom <= 0.5} aria-label="축소"><ZoomOut className="size-4" /></button><output aria-live="polite">{Math.round(zoom * 100)}%</output><button type="button" onClick={() => changeZoom(zoom + 0.1)} disabled={zoom >= 1.6} aria-label="확대"><ZoomIn className="size-4" /></button><button type="button" onClick={fitGraph} aria-label="화면에 맞춤" title="화면에 맞춤"><Maximize2 className="size-4" /></button></div></div></div>
    <div
      className={`attack-graph__viewport mt-5 ${dragging ? "is-dragging" : ""}`}
      onWheel={(event) => { if (event.ctrlKey || event.metaKey) { event.preventDefault(); changeZoom(zoom + (event.deltaY < 0 ? 0.1 : -0.1)); } }}
      onPointerDown={(event) => {
        if ((event.target as Element).closest("button")) return;
        event.currentTarget.setPointerCapture(event.pointerId);
        setDragging(true);
        setDragOrigin({ x: event.clientX - pan.x, y: event.clientY - pan.y });
      }}
      onPointerMove={(event) => { if (dragging) setPan({ x: event.clientX - dragOrigin.x, y: event.clientY - dragOrigin.y }); }}
      onPointerUp={(event) => { if (event.currentTarget.hasPointerCapture(event.pointerId)) event.currentTarget.releasePointerCapture(event.pointerId); setDragging(false); }}
      onPointerCancel={() => setDragging(false)}
    >
      <div className="attack-graph__stage" style={{ minWidth: `${Math.max(760, nodes.length * 195)}px`, transform: `translate(${pan.x}px, ${pan.y}px) scale(${zoom})`, transition: dragging ? "none" : undefined }}><div className="flex items-center">
      {nodes.map((node, index) => { const Icon = node.icon; return <div key={node.id} className="flex min-w-0 flex-1 items-center">
        <button type="button" onClick={() => setActive(index)} className={`attack-node attack-node--${node.color} ${active === index ? "is-active" : ""}`} aria-pressed={active === index}>
          <span className="attack-node__icon"><Icon className="size-5" /></span><span className="text-left"><small>{node.label}</small><strong>{node.title}</strong><em>{node.detail}</em></span>
        </button>
        {index < nodes.length - 1 && <div className="attack-edge"><span>{nodes[index + 1].label}</span><i /></div>}
      </div>; })}
      </div></div>
    </div>
    <p className="mt-2 text-right text-[0.7rem] text-muted-foreground">빈 공간을 드래그해 이동 · 버튼 또는 Ctrl/⌘ + 휠로 확대·축소</p>
    <div className="mt-2 flex items-center gap-3 rounded-lg border border-white/8 bg-black/20 p-3"><span className="grid size-10 shrink-0 place-items-center rounded-lg bg-cyan-400/10 text-cyan-300"><SelectedIcon className="size-5" /></span><div className="min-w-0"><p className="text-xs text-muted-foreground">선택한 노드 · {selected.label}</p><p className="mt-1 truncate text-sm font-semibold">{selected.title}</p><p className="mt-1 line-clamp-2 text-xs leading-5 text-muted-foreground">{selected.detail}</p></div></div>
  </section>;
}

function IncidentDetail({ incident, open, onOpenChange, timezone }: { incident: Incident | null; open: boolean; onOpenChange: (open: boolean) => void; timezone: Timezone }) {
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
          <TabsList variant="line" className="w-full justify-start overflow-x-auto border-b border-white/8 bg-[#0b121c] px-5 py-2">
            <TabsTrigger value="summary" className="flex-none px-4">판정 요약</TabsTrigger>
            <TabsTrigger value="evidence" className="flex-none px-4">타임라인·증거</TabsTrigger>
            <TabsTrigger value="extensions" className="flex-none px-4">ATT&CK·대응</TabsTrigger>
            <TabsTrigger value="diagnostics" className="flex-none px-4">조사 범위</TabsTrigger>
          </TabsList>

          <div className="min-h-0 flex-1 overflow-y-auto p-5 sm:p-6">
            <TabsContent value="summary" className="space-y-5">
              <IncidentGraph incident={incident} timezone={timezone} />
              <section className="grid gap-4 lg:grid-cols-[1.5fr_0.8fr]">
                <article className="signal-card p-5">
                  <p className="text-xs font-semibold uppercase tracking-[0.14em] text-cyan-300">Provisional conclusion</p>
                  <p className="mt-4 text-base leading-7 text-slate-200">{incident.summary}</p>
                  <div className="mt-5 border-t border-white/8 pt-5">
                    <p className="text-sm font-semibold">판정 근거</p>
                    <p className="mt-2 text-sm leading-7 text-muted-foreground">{incident.reasoning}</p>
                  </div>
                </article>
                <article className="signal-card p-5">
                  <p className="text-sm font-semibold">조사 신호</p>
                  <div className="mt-5 space-y-4">
                    <div><div className="flex justify-between text-xs"><span className="text-muted-foreground">판정 확신도 · LLM</span><span className="font-mono text-slate-200">{percent(incident.verdictConfidence)}</span></div><div className="mt-2 h-1.5 rounded-full bg-white/6"><div className="h-full rounded-full bg-violet-400" style={{ width: percent(incident.verdictConfidence) }} /></div></div>
                    <div><div className="flex justify-between text-xs"><span className="text-muted-foreground">증거 누적 점수</span><span className="font-mono text-slate-200">{percent(incident.investigationConfidence)}</span></div><div className="mt-2 h-1.5 rounded-full bg-white/6"><div className="h-full rounded-full bg-cyan-400" style={{ width: percent(incident.investigationConfidence) }} /></div></div>
                  </div>
                  <div className="mt-6 grid grid-cols-2 gap-3">
                    <div className="rounded-lg border border-white/8 bg-white/[0.02] p-3"><p className="text-xs text-muted-foreground">지지 증거</p><p className="mt-2 font-mono text-xl">{incident.evidence.length}</p></div>
                    <div className="rounded-lg border border-white/8 bg-white/[0.02] p-3"><p className="text-xs text-muted-foreground">반박 증거</p><p className="mt-2 font-mono text-xl">{incident.contradictingEvidence.length}</p></div>
                  </div>
                </article>
              </section>

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

            <TabsContent value="evidence" className="grid gap-5 xl:grid-cols-[0.8fr_1.2fr]">
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
                    <div className="flex flex-wrap items-center gap-2"><span className="font-mono text-xs text-cyan-300">E{item.sequence}</span><Badge variant="outline" className="border-white/10 text-slate-300">{item.layer}</Badge><Badge variant="outline" className={item.stance === "supporting" ? "border-emerald-400/20 text-emerald-300" : "border-amber-400/20 text-amber-300"}>{item.stance === "supporting" ? "지지" : "반박"}</Badge><span className="ml-auto font-mono text-xs text-muted-foreground">{formatDate(item.time, timezone)}</span></div>
                    <p className="mt-3 text-sm leading-6 text-slate-200">{item.description}</p>
                    <details className="mt-3 rounded-lg border border-white/8 bg-black/15 px-3 py-2"><summary className="cursor-pointer text-xs text-muted-foreground">원본 참조 {item.rawRefs.length}개</summary><div className="mt-2 flex flex-wrap gap-2">{item.rawRefs.length ? item.rawRefs.map((ref) => <code key={ref} className="rounded bg-white/5 px-2 py-1 text-xs text-cyan-200">{ref}</code>) : <span className="text-xs text-amber-300">참조 없음</span>}</div></details>
                  </div>)}
                </div>
              </section>
            </TabsContent>

            <TabsContent value="extensions" className="space-y-5">
              <div className="grid gap-5 lg:grid-cols-3">
                {[
                  { icon: Network, title: "ATT&CK 매핑", step: "⑦", text: "Technique ID, 전술, 매핑 근거가 이곳에 표시됩니다." },
                  { icon: Sparkles, title: "대응 생성", step: "⑧", text: "권고 조치, 영향 범위, 롤백 정보가 이곳에 표시됩니다." },
                  { icon: Waypoints, title: "자율성 레벨", step: "⑨", text: "L0/L1/L2와 실행·승인 상태가 이곳에 표시됩니다." },
                ].map((item) => { const Icon = item.icon; return <article key={item.title} className="signal-card min-h-56 p-5"><div className="flex items-center justify-between"><div className="grid size-10 place-items-center rounded-lg border border-violet-400/20 bg-violet-400/8 text-violet-300"><Icon className="size-5"/></div><span className="font-mono text-xs text-slate-500">STEP {item.step}</span></div><h3 className="mt-5 font-semibold">{item.title}</h3><p className="mt-2 text-sm leading-6 text-muted-foreground">{item.text}</p><Badge variant="outline" className="mt-5 border-slate-600/40 text-slate-400">산출물 연결 예정</Badge></article>; })}
              </div>
              <div className="rounded-xl border border-cyan-400/15 bg-cyan-400/5 p-5 text-sm leading-6 text-cyan-100/70">현재 조사 에이전트 결과만 연결되어 있습니다. 후속 단계 스키마가 확정되면 이 영역에 데이터만 연결하도록 자리를 분리했습니다.</div>
            </TabsContent>

            <TabsContent value="diagnostics" className="space-y-5">
              <section className="signal-card p-5">
                <div className="flex flex-wrap items-center justify-between gap-3"><div><h3 className="text-sm font-semibold">조사 범위</h3><p className="mt-1 text-xs text-muted-foreground">도구 원문 대신 확인한 계층과 결과 건수를 요약합니다.</p></div><span className="font-mono text-xs text-muted-foreground">{incident.statistics.toolCalls} calls</span></div>
                <div className="mt-5 flex flex-wrap gap-2">{layers.map((layer) => <Badge key={layer} variant="outline" className="border-cyan-400/20 bg-cyan-400/5 text-cyan-200">{layer}</Badge>)}</div>
              </section>
              <section className="signal-card overflow-hidden">
                <div className="border-b border-white/8 p-5"><h3 className="text-sm font-semibold">도구 실행 요약</h3></div>
                <div className="divide-y divide-white/7">{incident.tools.map((tool) => <details key={`${tool.sequence}-${tool.name}`} className="group p-5"><summary className="flex cursor-pointer list-none items-center gap-3"><span className={`size-2 rounded-full ${tool.success ? "bg-emerald-400" : "bg-rose-400"}`}/><span className="font-mono text-sm text-cyan-200">{tool.name}</span><span className="text-xs text-muted-foreground">{tool.resultCount} records</span><ChevronRight className="ml-auto size-4 text-slate-600 transition group-open:rotate-90"/></summary><p className="mt-3 pl-5 text-sm leading-6 text-muted-foreground">{tool.summary}</p></details>)}</div>
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
  { step: "07", title: "ATT&CK 매핑", subtitle: "RAG · ID 검증", status: "planned", icon: Network },
  { step: "08", title: "대응 생성", subtitle: "근거 기반 조치", status: "planned", icon: Sparkles },
  { step: "09", title: "자율성 레벨", subtitle: "L0 · L1 · L2", status: "planned", icon: Waypoints },
  { step: "10", title: "대시보드", subtitle: "판정 · 근거 · 운영", status: "frame", icon: LayoutDashboard },
];

function Pipeline() {
  return (
    <div className="space-y-5">
      <section className="signal-card p-5 sm:p-6">
        <PanelTitle icon={GitBranch} title="SSOC 파이프라인 스냅샷" description="현재 구현 상태와 후속 단계 연결 위치" trailing={<Badge variant="outline" className="border-cyan-400/20 text-cyan-300">Demo pipeline</Badge>} />
        <div className="mt-8 grid gap-3 lg:grid-cols-5">
          {pipelineSteps.map((item, index) => {
            const Icon = item.icon;
            return <div key={item.step} className="relative">
              <div className={`h-full min-h-36 rounded-xl border p-4 ${item.status === "active" ? "border-emerald-400/20 bg-emerald-400/[0.035]" : item.status === "frame" ? "border-cyan-400/30 bg-cyan-400/[0.06]" : "border-dashed border-slate-600/35 bg-black/10"}`}>
                <div className="flex items-center justify-between"><span className="font-mono text-[0.68rem] text-slate-500">STEP {item.step}</span><span className={`size-2 rounded-full ${item.status === "active" ? "bg-emerald-400" : item.status === "frame" ? "bg-cyan-400" : "border border-slate-500"}`}/></div>
                <Icon className={`mt-5 size-5 ${item.status === "active" ? "text-emerald-300" : item.status === "frame" ? "text-cyan-300" : "text-slate-500"}`}/>
                <h3 className="mt-3 text-sm font-semibold">{item.title}</h3><p className="mt-1 text-xs leading-5 text-muted-foreground">{item.subtitle}</p>
              </div>
              {index < pipelineSteps.length - 1 && <ArrowRight className="absolute -right-[0.68rem] top-1/2 z-10 hidden size-4 -translate-y-1/2 text-slate-600 lg:block"/>}
            </div>;
          })}
        </div>
        <div className="mt-5 flex flex-wrap gap-4 text-xs text-muted-foreground"><span className="flex items-center gap-2"><i className="size-2 rounded-full bg-emerald-400"/>구현·연결됨</span><span className="flex items-center gap-2"><i className="size-2 rounded-full bg-cyan-400"/>현재 대시보드 틀</span><span className="flex items-center gap-2"><i className="size-2 rounded-full border border-slate-500"/>후속 산출물 대기</span></div>
      </section>

      <section className="grid gap-5 xl:grid-cols-[0.85fr_1.15fr]">
        <article className="signal-card p-5 sm:p-6">
          <PanelTitle icon={Server} title="모델 연결" description="코드 구성 기준 스냅샷" />
          <div className="mt-6 space-y-3">
            <div className="rounded-xl border border-cyan-400/20 bg-cyan-400/[0.04] p-4"><div className="flex items-center justify-between"><div><p className="text-xs text-muted-foreground">기본 Provider</p><p className="mt-2 font-medium">Google Gemini</p></div><Badge variant="outline" className="border-cyan-400/20 text-cyan-300">Default</Badge></div><p className="mt-3 font-mono text-xs text-slate-300">gemini-3.5-flash-lite</p></div>
            <div className="rounded-xl border border-white/8 bg-white/[0.02] p-4"><p className="text-xs text-muted-foreground">지원 Provider</p><p className="mt-2 font-medium">Anthropic Claude</p><p className="mt-3 text-xs text-muted-foreground">환경 설정으로 교체 가능</p></div>
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
  const incidents = resultData.incidents;
  const [view, setView] = useState<View>("overview");
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [detailOpen, setDetailOpen] = useState(false);
  const [timezone, setTimezone] = useState<Timezone>("UTC");
  const active = navigation.find((item) => item.id === view) ?? navigation[0];

  const openIncident = (incident: Incident) => {
    setSelectedIncident(incident);
    setDetailOpen(true);
  };

  return (
    <main className="min-h-screen bg-background text-foreground">
      <aside className="fixed inset-y-0 left-0 z-20 hidden w-64 border-r border-border bg-sidebar/95 backdrop-blur-xl lg:flex lg:flex-col">
        <div className="flex h-20 items-center gap-3 border-b border-border px-6">
          <div className="grid size-10 place-items-center rounded-lg border border-cyan-400/30 bg-cyan-400/10 text-cyan-300"><Shield className="size-5" /></div>
          <div><p className="text-xl font-black tracking-[0.18em]">SSOC</p><p className="text-xs text-muted-foreground">Security Signal Operations</p></div>
        </div>
        <nav className="space-y-1 p-4" aria-label="주요 메뉴">
          {navigation.map((item) => { const Icon = item.icon; const isActive = item.id === view; return <button key={item.id} onClick={() => setView(item.id)} className={`relative flex w-full items-center gap-3 border-0 px-3 py-3 text-left transition ${isActive ? "text-cyan-200 before:absolute before:inset-y-2 before:left-0 before:w-0.5 before:rounded-full before:bg-cyan-300" : "text-muted-foreground hover:text-foreground"}`}><Icon className="size-4"/><span className="flex-1"><span className="block text-sm font-medium">{item.label}</span><span className="mt-0.5 block text-xs opacity-65">{item.description}</span></span></button>; })}
        </nav>
        <div className="mt-auto border-t border-border p-4">
          <div className="rounded-lg border border-amber-400/20 bg-amber-400/5 p-3"><p className="flex items-center gap-2 text-xs font-semibold text-amber-300"><CircleDot className="size-3.5"/> DEMO DATA</p><p className="mt-1 text-xs leading-5 text-muted-foreground">000/results의 샘플 조사 결과를 표시합니다.</p></div>
        </div>
      </aside>

      <section className="lg:pl-64">
        <header className="sticky top-0 z-10 border-b border-border bg-background/90 backdrop-blur-xl">
          <div className="flex h-20 items-center justify-between gap-4 px-5 sm:px-8">
            <div className="flex min-w-0 items-center gap-3"><div className="grid size-9 place-items-center rounded-lg border border-cyan-400/20 bg-cyan-400/8 text-cyan-300 lg:hidden"><Shield className="size-4"/></div><div><p className="truncate text-sm text-muted-foreground">{active.description}</p><h1 className="truncate text-xl font-bold tracking-tight">{active.label}</h1></div></div>
            <div className="flex items-center gap-3"><div className="hidden items-center gap-2 rounded-full border border-emerald-400/20 bg-emerald-400/5 px-3 py-2 text-xs text-emerald-300 sm:flex"><span className="size-2 rounded-full bg-emerald-400"/> 조사 결과 {incidents.length}건 연결</div><div className="flex items-center rounded-lg border border-white/10 bg-black/20 p-1" aria-label="시간대 선택">{(["UTC", "KST"] as const).map((zone) => <button type="button" key={zone} onClick={() => setTimezone(zone)} aria-pressed={timezone === zone} className={`min-w-12 rounded-md px-3 py-2 font-mono text-xs font-semibold transition ${timezone === zone ? "bg-cyan-400 text-[#041112]" : "text-muted-foreground hover:text-foreground"}`}>{zone}</button>)}</div></div>
          </div>
          <nav className="flex overflow-x-auto border-t border-white/6 px-3 lg:hidden" aria-label="모바일 메뉴">{navigation.map((item) => { const Icon = item.icon; return <button key={item.id} onClick={() => setView(item.id)} className={`flex min-w-max items-center gap-2 border-b-2 px-3 py-3 text-sm ${view === item.id ? "border-cyan-300 text-cyan-200" : "border-transparent text-muted-foreground"}`}><Icon className="size-4"/>{item.label}</button>; })}</nav>
        </header>

        <div className="p-4 sm:p-6 2xl:p-8">
          {view === "overview" && <Overview incidents={incidents} onOpenIncident={openIncident} timezone={timezone} />}
          {view === "incidents" && <IncidentList incidents={incidents} onOpenIncident={openIncident} timezone={timezone} />}
          {view === "operations" && <Operations incidents={incidents} />}
          {view === "pipeline" && <Pipeline />}
        </div>
      </section>

      <IncidentDetail incident={selectedIncident} open={detailOpen} onOpenChange={setDetailOpen} timezone={timezone} />
    </main>
  );
}
