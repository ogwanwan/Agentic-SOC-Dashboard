"use client";

import { useEffect, useMemo, useState } from "react";
import { ArrowRight, Check, ClipboardCopy, Download, ExternalLink, FileCode2, Fingerprint, RotateCcw, Search, ShieldCheck, Sparkles, TerminalSquare, TriangleAlert, X } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { actionFingerprint, actionTechniques, currentReview, entryStatus, flattenResponses, normalizedActionKey, responseStatistics, reviewStorageKey, riskLabels, safeSourceUrl, statusLabel, techniqueUrl, type ResponseEntry, type ResponseIncident, type Reviews } from "@/lib/response";

type Props = {
  incidents: ResponseIncident[];
  timezone: "UTC" | "KST";
  onOpenIncident: (incident: ResponseIncident) => void;
  incidentId?: string | null;
};

function dateLabel(value: string | undefined, timezone: "UTC" | "KST") {
  if (!value || !Number.isFinite(Date.parse(value))) return "미기록";
  return new Intl.DateTimeFormat("ko-KR", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false, timeZone: timezone === "KST" ? "Asia/Seoul" : "UTC" }).format(new Date(value));
}
function Status({ value }: { value: string }) {
  const tone = value === "verified" ? "border-emerald-400/25 bg-emerald-400/8 text-emerald-200"
    : ["failed", "verification_failed", "rolled_back"].includes(value) ? "border-rose-400/25 bg-rose-400/8 text-rose-200"
    : ["running", "verifying", "reviewed"].includes(value) ? "border-cyan-400/25 bg-cyan-400/8 text-cyan-200"
    : value === "excluded" ? "border-slate-500/25 text-slate-400" : "border-amber-400/25 bg-amber-400/8 text-amber-200";
  return <Badge variant="outline" className={`whitespace-nowrap ${tone}`}>{statusLabel(value)}</Badge>;
}
function Risk({ value }: { value: string }) {
  return <Badge variant="outline" className={value === "LOW" ? "border-emerald-400/20 text-emerald-200" : ["HIGH", "CRITICAL"].includes(value) ? "border-rose-400/20 text-rose-200" : "border-amber-400/20 text-amber-200"}>{riskLabels[value] ?? "미평가"}</Badge>;
}
function Empty({ title, text }: { title: string; text: string }) {
  return <div className="p-10 text-center"><ShieldCheck aria-hidden="true" className="mx-auto size-8 text-slate-500"/><h3 className="mt-4 font-semibold">{title}</h3><p className="mx-auto mt-2 max-w-xl text-sm leading-6 text-muted-foreground">{text}</p></div>;
}
function downloadJson(filename: string, value: unknown) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(value, null, 2)], { type: "application/json" }));
  const anchor = document.createElement("a");
  anchor.href = url; anchor.download = filename; anchor.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function ResponseCenter({ incidents, timezone, onOpenIncident, incidentId }: Props) {
  const entries = useMemo(() => flattenResponses(incidents), [incidents]);
  const [tab, setTab] = useState("recommendations");
  const [query, setQuery] = useState("");
  const [host, setHost] = useState("all");
  const [category, setCategory] = useState("all");
  const [technique, setTechnique] = useState("all");
  const [stateFilter, setStateFilter] = useState("all");
  const [incidentFilter, setIncidentFilter] = useState<string | null>(incidentId ?? null);
  const [selectedKey, setSelectedKey] = useState<string | null>(null);
  const [reviews, setReviews] = useState<Reviews>({});
  const [storageReady, setStorageReady] = useState(false);
  const [noteDraft, setNoteDraft] = useState<{ key: string; text: string } | null>(null);
  const [message, setMessage] = useState("");
  const [requestOpen, setRequestOpen] = useState(false);
  const [pageIndex, setPageIndex] = useState(0);

  useEffect(() => {
    const loadReviews = () => { try {
      const parsed = JSON.parse(localStorage.getItem(reviewStorageKey) || "{}");
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
        const valid = Object.fromEntries(Object.entries(parsed).filter(([, value]) => {
          const record = value as Partial<Reviews[string]> | null;
          return record && ["reviewed", "excluded"].includes(record.decision ?? "") && typeof record.note === "string" && typeof record.updatedAt === "string" && typeof record.fingerprint === "string";
        }));
        setReviews(valid as Reviews);
      }
    } catch { setMessage("검토 기록을 읽지 못했습니다. 브라우저 저장소를 확인해 주세요."); }
    setStorageReady(true); };
    const timer = window.setTimeout(loadReviews, 0);
    const onStorage = (event: StorageEvent) => { if (event.key === reviewStorageKey) loadReviews(); };
    window.addEventListener("storage", onStorage);
    return () => { window.clearTimeout(timer); window.removeEventListener("storage", onStorage); };
  }, []);

  const hosts = [...new Set(entries.map((entry) => entry.incident.host))].sort();
  const categories = [...new Map(entries.map((entry) => [entry.action.category, entry.action.categoryLabel])).entries()];
  const techniques = [...new Set(entries.flatMap((entry) => actionTechniques(entry.action)))].sort();
  const filtered = entries.filter((entry) => {
    const text = [entry.action.title, entry.action.target, entry.action.reason, entry.incident.incidentId, entry.incident.title, entry.incident.host, ...actionTechniques(entry.action)].join(" ").toLowerCase();
    return (!query || text.includes(query.toLowerCase())) && (host === "all" || entry.incident.host === host)
      && (category === "all" || entry.action.category === category) && (technique === "all" || actionTechniques(entry.action).includes(technique))
      && (!incidentFilter || entry.incident.incidentId === incidentFilter) && (stateFilter === "all" || entryStatus(entry, reviews) === stateFilter);
  });
  const pageCount = Math.max(1, Math.ceil(filtered.length / 10));
  const page = Math.min(pageIndex, pageCount - 1);
  const paginated = filtered.slice(page * 10, (page + 1) * 10);
  const selected = filtered.find((entry) => entry.key === selectedKey) ?? paginated[0] ?? null;
  const review = selected ? currentReview(selected, reviews) : undefined;
  const note = selected && noteDraft?.key === selected.key ? noteDraft.text : review?.note ?? "";
  const stats = responseStatistics(filtered);
  const openCount = entries.filter((entry) => !entry.action.execution && currentReview(entry, reviews)?.decision !== "excluded").length;
  const pendingCount = filtered.filter((entry) => ["review", "needs_details"].includes(entryStatus(entry, reviews))).length;
  const reviewedCount = filtered.filter((entry) => entryStatus(entry, reviews) === "reviewed").length;
  const executionEntries = filtered.filter((entry) => entry.action.execution || currentReview(entry, reviews));
  const linkedIncidents = new Set(filtered.map((entry) => entry.incident.incidentId));
  const actualStatuses = [...new Set(entries.map((entry) => entryStatus(entry, reviews)))];

  function selectEntry(entry: ResponseEntry) {
    setSelectedKey(entry.key); setNoteDraft({ key: entry.key, text: currentReview(entry, reviews)?.note ?? "" }); setMessage("");
  }
  function saveReview(decision: "reviewed" | "excluded") {
    if (!selected || !storageReady || selected.action.execution) return;
    if (decision === "excluded" && !note.trim()) { setMessage("적용 제외 사유를 입력해 주세요."); return; }
    const next = { ...reviews, [selected.key]: { decision, note: note.trim(), updatedAt: new Date().toISOString(), fingerprint: actionFingerprint(selected) } };
    try { localStorage.setItem(reviewStorageKey, JSON.stringify(next)); setReviews(next); setMessage(decision === "reviewed" ? "검토 완료를 이 브라우저에 기록했습니다." : "적용 제외 사유를 이 브라우저에 기록했습니다."); }
    catch { setMessage("저장 공간에 접근할 수 없어 검토 기록을 저장하지 못했습니다."); }
  }
  function resetReview() {
    if (!selected) return;
    const next = { ...reviews }; delete next[selected.key];
    try { localStorage.setItem(reviewStorageKey, JSON.stringify(next)); setReviews(next); setNoteDraft(null); setMessage("검토 상태를 되돌렸습니다."); }
    catch { setMessage("검토 상태를 되돌리지 못했습니다."); }
  }
  async function copyCommand() {
    if (!selected?.action.commandHint) return;
    try { await navigator.clipboard.writeText(selected.action.commandHint); setMessage("명령 참고를 복사했습니다. 서버 상태와 대상을 확인한 후 사용하세요."); }
    catch { setMessage("복사하지 못했습니다. 명령 참고를 직접 선택해 복사해 주세요."); }
  }
  function exportRequest() {
    if (!selected) return;
    downloadJson(`ssoc-${selected.incident.incidentId}-${selected.action.id}-request.json`, {
      schemaVersion: 1, type: "manual_response_request", exportedAt: new Date().toISOString(),
      incidentId: selected.incident.incidentId, investigationId: selected.incident.investigationId,
      host: selected.incident.host, sourceFile: selected.response.sourceFile,
      recommendation: selected.action, review: currentReview(selected, reviews) ?? null,
      executionRequested: false,
    });
    setMessage("적용 요청서를 내려받았습니다. 서버 실행이나 승인 전송은 수행하지 않았습니다.");
    setRequestOpen(false);
  }

  const typeCounts = categories.map(([name, label]) => ({ label, count: filtered.filter((entry) => entry.action.category === name).length }));
  const techniqueCounts = techniques.map((id) => ({ id, count: filtered.filter((entry) => actionTechniques(entry.action).includes(id)).length })).filter((item) => item.count).sort((a, b) => b.count - a.count).slice(0, 8);
  const groups = new Map<string, { label: string; host: string; incidents: Set<string>; count: number }>();
  for (const entry of filtered) {
    const key = normalizedActionKey(entry);
    const group = groups.get(key) ?? { label: entry.action.title, host: entry.incident.host, incidents: new Set<string>(), count: 0 };
    group.incidents.add(entry.incident.incidentId); group.count++; groups.set(key, group);
  }
  const repeats = [...groups.values()].filter((group) => group.incidents.size >= 2).sort((a, b) => b.incidents.size - a.incidents.size).slice(0, 5);
  const mappedPairs = new Set(incidents.filter((incident) => !incidentFilter || incident.incidentId === incidentFilter).filter((incident) => host === "all" || incident.host === host).flatMap((incident) => (incident.attackMapping?.techniques ?? []).map((item) => `${incident.incidentId}::${item.id}`)));
  const coveredPairs = new Set(filtered.flatMap((entry) => actionTechniques(entry.action).map((id) => `${entry.incident.incidentId}::${id}`)).filter((key) => mappedPairs.has(key)));

  return <div className="space-y-5">
    <Tabs value={tab} onValueChange={setTab}>
      <div className="flex flex-wrap items-center justify-between gap-3">
        <TabsList variant="line" className="flex-wrap"><TabsTrigger value="recommendations">권고 사항 <span className="ml-1.5 rounded-full bg-cyan-400/10 px-2 text-xs text-cyan-200">{openCount}</span></TabsTrigger><TabsTrigger value="progress">적용 현황</TabsTrigger><TabsTrigger value="statistics">통계</TabsTrigger></TabsList>
        <Button variant="outline" size="sm" onClick={() => downloadJson("ssoc-response-export.json", { exportedAt: new Date().toISOString(), filters: { query, host, category, technique, stateFilter, incidentFilter }, recommendations: filtered.map((entry) => ({ incidentId: entry.incident.incidentId, investigationId: entry.incident.investigationId, host: entry.incident.host, sourceFile: entry.response.sourceFile, action: entry.action, review: currentReview(entry, reviews) ?? null })) })}><Download className="size-4"/>현재 목록 내보내기</Button>
      </div>

      <section className="signal-card mt-3 p-4" aria-label="대응 권고 필터">
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-[1.5fr_1fr_1fr_1fr_1fr]">
          <label className="space-y-1.5"><span className="text-xs text-muted-foreground">검색</span><span className="relative block"><Search aria-hidden="true" className="absolute left-3 top-3 size-4 text-slate-500"/><Input className="pl-9" placeholder="권고, 사건, 대상 검색" value={query} onChange={(event) => setQuery(event.target.value)} /></span></label>
          <Filter label="대상 서버" value={host} onChange={setHost} options={hosts.map((value) => [value, value])}/>
          <Filter label="조치 유형" value={category} onChange={setCategory} options={categories}/>
          <Filter label="ATT&CK 기법" value={technique} onChange={setTechnique} options={techniques.map((value) => [value, value])}/>
          <Filter label="상태" value={stateFilter} onChange={setStateFilter} options={actualStatuses.map((value) => [value, statusLabel(value)])}/>
        </div>
        <div className="mt-3 flex flex-wrap items-center gap-3 text-xs text-muted-foreground"><span>{filtered.length}개 권고 · 사건 {linkedIncidents.size}건 · 현재 필터 기준</span>{incidentFilter && <button className="inline-flex items-center gap-2 rounded-md border border-cyan-400/25 px-2 py-1 text-cyan-200" onClick={() => setIncidentFilter(null)}>사건 {incidentFilter}<X className="size-3"/><span className="sr-only">사건 필터 해제</span></button>}{(query || host !== "all" || category !== "all" || technique !== "all" || stateFilter !== "all") && <button className="text-cyan-300 underline underline-offset-4" onClick={() => { setQuery(""); setHost("all"); setCategory("all"); setTechnique("all"); setStateFilter("all"); }}>필터 초기화</button>}</div>
      </section>

      <TabsContent value="recommendations" className="mt-4 space-y-4">
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
          <Metric label="검토 대기" value={pendingCount} note="즉시 조치와 확인 필요 권고" icon={Sparkles}/>
          <Metric label="검토 완료" value={reviewedCount} note="이 브라우저의 검토 기록 · 실행 아님" icon={Check}/>
          <Metric label="명령 참고 제공" value={filtered.filter((entry) => entry.action.commandHint).length} note="사전 점검 전 · 적용 준비 상태 아님" icon={TerminalSquare}/>
          <Metric label="검증 완료" value={stats.withExecution.length ? stats.verified.length : "—"} note={stats.withExecution.length ? "실행 산출물 기준" : "실행 결과 미연결"} icon={ShieldCheck}/>
        </div>
        <div className="flex items-start gap-3 rounded-xl border border-cyan-400/15 bg-cyan-400/4 px-4 py-3 text-xs leading-5 text-muted-foreground"><TerminalSquare className="mt-0.5 size-4 shrink-0 text-cyan-300"/><p>L2는 자동화 후보입니다. 서버 실행기는 아직 연결되지 않았으며 명령 복사와 적용 요청서 내보내기를 사용할 수 있습니다. 검토·제외 기록은 이 브라우저에만 저장됩니다.</p></div>
        <div className="grid items-start gap-4 2xl:grid-cols-[minmax(0,1fr)_400px]">
          <section className="signal-card overflow-hidden">
            <div className="border-b border-white/8 p-5"><h2 className="font-semibold">바로 확인할 권고</h2><p className="mt-1 text-xs text-muted-foreground">사건 심각도 → 조치 우선순위 순으로 정렬합니다.</p></div>
            {filtered.length ? <Table className="min-w-[760px]"><TableHeader><TableRow><TableHead>상태</TableHead><TableHead>대응 권고</TableHead><TableHead>대상</TableHead><TableHead>근거</TableHead><TableHead>영향</TableHead><TableHead><span className="sr-only">권고 검토</span></TableHead></TableRow></TableHeader><TableBody>{paginated.map((entry) => <TableRow key={entry.key} data-state={selected?.key === entry.key ? "selected" : undefined} className="align-top" onClick={() => selectEntry(entry)}><TableCell><Status value={entryStatus(entry, reviews)}/></TableCell><TableCell className="max-w-80 min-w-48 whitespace-normal"><button onClick={() => selectEntry(entry)} className="text-left font-medium leading-6 text-slate-100">{entry.action.title}</button><p className="mt-1 text-xs text-muted-foreground">{entry.action.categoryLabel} · {entry.action.priority ? `우선순위 ${entry.action.priority}` : "우선순위 미지정"}</p></TableCell><TableCell className="max-w-56 whitespace-normal"><p className="break-all font-mono text-xs leading-5">{entry.action.target || "대상 확인 필요"}</p><p className="mt-1 text-xs text-muted-foreground">{entry.incident.host}</p></TableCell><TableCell className="min-w-32"><div className="flex flex-wrap gap-1">{actionTechniques(entry.action).map((id) => <code key={id} className="text-xs text-violet-300">{id}</code>)}</div><button className="mt-1 block font-mono text-xs text-cyan-300 underline-offset-4 hover:underline" onClick={(event) => { event.stopPropagation(); onOpenIncident(entry.incident); }}>{entry.incident.incidentId}</button><p className="mt-1 text-xs text-muted-foreground">{entry.incident.severity}</p></TableCell><TableCell><Risk value={entry.action.risk}/><p className="mt-1 text-xs text-muted-foreground">{entry.action.autonomy || "레벨 미지정"}</p></TableCell><TableCell><Button variant="outline" size="sm" onClick={() => selectEntry(entry)}>검토</Button></TableCell></TableRow>)}</TableBody></Table> : <Empty title={entries.length ? "조건에 맞는 권고가 없습니다" : "연결된 대응 권고가 없습니다"} text={entries.length ? "검색어나 필터를 변경해 주세요." : "results/response의 사건별 대응 JSON이 생성되면 목록이 자동으로 갱신됩니다."}/>}
            {pageCount > 1 && <div className="flex items-center justify-between gap-3 border-t border-white/8 p-4 text-xs text-muted-foreground"><span>{page + 1}/{pageCount} 페이지 · 총 {filtered.length}개</span><div className="flex gap-2"><Button variant="outline" size="sm" disabled={page === 0} onClick={() => setPageIndex(page - 1)}>이전</Button><Button variant="outline" size="sm" disabled={page === pageCount - 1} onClick={() => setPageIndex(page + 1)}>다음</Button></div></div>}
          </section>
          {selected && <aside className="signal-card overflow-hidden" aria-label="선택한 대응 권고 상세">
            <div className="border-b border-white/8 p-5"><div className="flex flex-wrap gap-2"><Status value={entryStatus(selected, reviews)}/><Risk value={selected.action.risk}/>{selected.action.requiresApproval && <Badge variant="outline" className="text-violet-300">승인 필요</Badge>}</div><h2 className="mt-3 font-semibold leading-6">{selected.action.title}</h2><p className="mt-1 break-all font-mono text-xs text-muted-foreground">{selected.incident.incidentId} · {selected.action.id}</p><button className="mt-3 inline-flex items-center gap-2 text-xs text-cyan-300" onClick={() => onOpenIncident(selected.incident)}>연결 사건과 증거 보기<ArrowRight className="size-3"/></button></div>
            <div className="px-5 py-3 text-xs text-muted-foreground">사건 → ATT&CK → 완화 근거 → 환경 맞춤 조치</div>
            <DetailSection title="생성 근거" icon={Fingerprint}><p className="text-sm leading-6 text-slate-300">{selected.action.reason || "생성 근거 미기록"}</p><div className="mt-3 flex flex-wrap gap-2">{actionTechniques(selected.action).map((id) => { const url = techniqueUrl(id); return url ? <a key={id} href={url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 rounded-md bg-violet-400/8 px-2 py-1 font-mono text-xs text-violet-200">{id}<ExternalLink className="size-3"/></a> : <code key={id}>{id}</code>; })}</div><p className="mt-2 text-xs text-muted-foreground">{selected.action.techniqueName} · ATT&CK {selected.response.attackVersion || "버전 미기록"}</p>
              {selected.action.mitigationSources?.length ? <ul className="mt-3 space-y-2">{selected.action.mitigationSources.map((source, index) => { const url = safeSourceUrl(source.url); return <li key={`${source.url}-${index}`} className="text-xs">{url ? <a className="text-cyan-300 underline underline-offset-4" href={url} target="_blank" rel="noreferrer">{source.title} <ExternalLink className="inline size-3"/></a> : <span>{source.title} · 링크 미확인</span>}<p className="mt-1 text-muted-foreground">{[source.mitigationId, source.version].filter(Boolean).join(" · ")}</p></li>; })}</ul> : <p className="mt-3 text-xs leading-5 text-amber-300/85">원본 산출물에 완화 문서 인용이 없습니다. 위 링크는 ATT&CK 기법 참고 링크이며 생성 시 사용한 출처를 보증하지 않습니다.</p>}
              {selected.response.selectionMode && <p className="mt-2 text-xs text-muted-foreground">조치 선택: {selected.response.selectionMode === "fallback" ? "템플릿 대체 선택" : selected.response.selectionMode}</p>}
            </DetailSection>
            <DetailSection title="적용 대상과 영향" icon={TerminalSquare}><dl className="space-y-2 text-sm"><div><dt className="text-xs text-muted-foreground">서버 · 대상</dt><dd className="mt-1 break-all">{selected.incident.host} · {selected.action.target || "확인 필요"}</dd></div><div><dt className="text-xs text-muted-foreground">예상 영향</dt><dd className="mt-1 leading-6 text-slate-300">{selected.action.sideEffects || "미기록"}</dd></div><div><dt className="text-xs text-muted-foreground">자율성 판정</dt><dd className="mt-1 leading-6 text-slate-300">{selected.action.autonomy} · {selected.action.autonomyLabel || "미기록"}<p className="mt-1 text-xs text-muted-foreground">{selected.action.autonomyReason}</p></dd></div></dl></DetailSection>
            <DetailSection title="명령 참고" icon={FileCode2}>{selected.action.commandHint ? <><pre className="max-h-64 overflow-auto rounded-lg border border-white/8 bg-black/20 p-3 text-xs leading-5 text-cyan-100"><code>{selected.action.commandHint}</code></pre><Button className="mt-2" variant="outline" size="sm" onClick={copyCommand}><ClipboardCopy className="size-3.5"/>명령 복사</Button></> : <p className="text-sm text-muted-foreground">명령이 제공되지 않았습니다. 대상과 수동 적용 절차를 확인하세요.</p>}</DetailSection>
            <DetailSection title="롤백과 사후 검증" icon={RotateCcw}><p className="text-xs text-muted-foreground">{selected.action.reversible ? "원복 가능" : "비가역 조치"}</p><p className="mt-2 text-sm leading-6 text-slate-300">{selected.action.rollback || "롤백 방법 미기록"}</p><p className="mt-3 text-xs text-muted-foreground">검증 방법</p><p className="mt-1 text-sm leading-6 text-slate-300">{selected.action.verification || "검증 방법 미기록"}</p></DetailSection>
            <DetailSection title="사전 확인과 사건 근거" icon={TriangleAlert}><ul className="space-y-2 text-xs leading-5 text-slate-300">{[...(selected.action.preconditions ?? []), ...selected.response.remainingUnknowns, ...selected.response.warnings, ...selected.response.errors].map((item, index) => <li key={`${index}-${item}`}>• {item}</li>)}</ul>{selected.action.evidenceIds.length > 0 && <div className="mt-3 flex flex-wrap gap-1.5">{selected.action.evidenceIds.map((id) => <code key={id} className="rounded bg-white/5 px-2 py-1 text-xs">{id}</code>)}</div>}</DetailSection>
            <div className="p-5">
              <label htmlFor="response-review-note" className="text-xs text-muted-foreground">검토 메모 · 제외 사유</label>
              <textarea id="response-review-note" value={note} onChange={(event) => setNoteDraft({ key: selected.key, text: event.target.value })} className="mt-2 min-h-20 w-full rounded-lg border border-input bg-black/15 p-3 text-sm" placeholder="검토 내용 또는 적용 제외 사유" disabled={Boolean(selected.action.execution)}/>
              <p className="mt-2 text-xs leading-5 text-muted-foreground">{review ? `로컬 기록 · ${dateLabel(review.updatedAt, timezone)} ${timezone}` : "검토 기록은 이 브라우저에 저장됩니다. 승인·서버 실행과 구분됩니다."}</p>
              <div className="mt-3 flex flex-wrap gap-2"><Button variant="outline" size="sm" onClick={() => saveReview("excluded")} disabled={!storageReady || Boolean(selected.action.execution)}>적용 제외</Button><Button variant="outline" size="sm" onClick={() => saveReview("reviewed")} disabled={!storageReady || Boolean(selected.action.execution)}><Check className="size-3.5"/>검토 완료</Button>{review && <Button variant="ghost" size="sm" onClick={resetReview}>검토 되돌리기</Button>}</div>
              <Button className="mt-3 w-full" onClick={() => setRequestOpen(true)} disabled={entryStatus(selected, reviews) === "excluded" || Boolean(selected.action.execution)}>적용 요청서 준비</Button>
            </div>
          </aside>}
        </div>
      </TabsContent>

      <TabsContent value="progress" className="mt-4 space-y-4">
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4"><Metric label="적용 중" value={stats.withExecution.filter((entry) => entry.action.execution?.status === "running").length} note="실행 결과 기준" icon={TerminalSquare}/><Metric label="검증 중" value={stats.withExecution.filter((entry) => entry.action.execution?.status === "verifying").length} note="실행 결과 기준" icon={ShieldCheck}/><Metric label="실패·롤백" value={stats.withExecution.filter((entry) => ["failed", "verification_failed", "rolled_back"].includes(entry.action.execution!.status)).length} note="실행 결과 기준" icon={RotateCcw}/><Metric label="검토·제외 기록" value={executionEntries.filter((entry) => currentReview(entry, reviews)).length} note="이 브라우저의 로컬 기록" icon={Check}/></div>
        <section className="signal-card overflow-hidden"><div className="border-b border-white/8 p-5"><h2 className="font-semibold">적용과 검토 이력</h2><p className="mt-1 text-xs leading-5 text-muted-foreground">실행 결과와 로컬 검토 기록을 구분해 표시합니다. 실행 결과가 없으면 적용·완료를 추정하지 않습니다.</p></div>{executionEntries.length ? <Table className="min-w-[760px]"><TableHeader><TableRow><TableHead>상태</TableHead><TableHead>조치·사건</TableHead><TableHead>기록 출처</TableHead><TableHead>결과</TableHead><TableHead>시각 {timezone}</TableHead></TableRow></TableHeader><TableBody>{executionEntries.map((entry) => { const execution = entry.action.execution; const local = currentReview(entry, reviews); return <TableRow key={entry.key}><TableCell><Status value={entryStatus(entry, reviews)}/></TableCell><TableCell className="whitespace-normal"><button className="text-left font-medium" onClick={() => { selectEntry(entry); setTab("recommendations"); }}>{entry.action.title}</button><p className="mt-1 text-xs text-muted-foreground">{entry.incident.incidentId} · {entry.incident.host}</p></TableCell><TableCell>{execution ? "실행 산출물" : "브라우저 로컬"}<p className="text-xs text-muted-foreground">{execution?.actor || ""}</p></TableCell><TableCell className="max-w-96 whitespace-normal text-sm text-muted-foreground">{execution ? [execution.result, execution.verificationResult].filter(Boolean).join(" · ") || "결과 설명 미기록" : local?.note || "검토 완료 · 메모 없음"}</TableCell><TableCell className="font-mono text-xs">{dateLabel(execution?.verifiedAt || execution?.completedAt || execution?.startedAt || execution?.requestedAt || local?.updatedAt, timezone)}</TableCell></TableRow>; })}</TableBody></Table> : <Empty title="아직 적용 결과가 없습니다" text="대응 생성기에는 권고만 기록되어 있습니다. 서버 실행 결과가 연결되면 적용·검증·롤백 이력이 표시됩니다. 검토 기록은 권고 상세에서 남길 수 있습니다."/>}</section>
      </TabsContent>

      <TabsContent value="statistics" className="mt-4 space-y-4">
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4"><Metric label="대응 기법 연결률" value={mappedPairs.size ? `${Math.round(coveredPairs.size / mappedPairs.size * 100)}%` : "—"} note={`${coveredPairs.size}/${mappedPairs.size} 사건·기법 연결 · 적용 효과 아님`} icon={Fingerprint}/><Metric label="검증 성공률" value={stats.verificationFinished.length ? `${Math.round(stats.verified.length / stats.verificationFinished.length * 100)}%` : "—"} note={stats.verificationFinished.length ? `검증 종료 ${stats.verificationFinished.length}건 기준` : "검증 결과 미연결"} icon={ShieldCheck}/><Metric label="중앙 대응 시간" value={stats.median !== null ? `${Math.round(stats.median)}분` : "—"} note={stats.median !== null ? `생성 → 검증 완료 · ${stats.durationSamples}건` : "생성·검증 시각 미기록"} icon={TerminalSquare}/><Metric label="통합 조치 후보" value={groups.size} note={`${filtered.length}개 권고 · 서버·대상·템플릿·명령 기준`} icon={Sparkles}/></div>
        <div className="grid gap-4 xl:grid-cols-3"><section className="signal-card p-5"><h2 className="font-semibold">조치 유형 분포</h2><p className="mt-1 text-xs text-muted-foreground">현재 필터 · 권고 단위</p><div className="mt-5 space-y-4">{typeCounts.map((item) => <CountBar key={item.label} label={item.label} value={item.count} max={Math.max(...typeCounts.map((row) => row.count), 1)}/>)}{!filtered.length && <p className="text-sm text-muted-foreground">집계할 권고가 없습니다.</p>}</div></section><section className="signal-card p-5"><h2 className="font-semibold">기법별 대응 권고</h2><p className="mt-1 text-xs text-muted-foreground">다중 기법 권고는 각 기법에 집계</p><div className="mt-5 space-y-3">{techniqueCounts.map((item) => <CountBar key={item.id} label={item.id} value={item.count} max={Math.max(...techniqueCounts.map((row) => row.count), 1)} onClick={() => { setTechnique(item.id); setTab("recommendations"); }}/>)}</div></section><section className="signal-card p-5"><h2 className="font-semibold">반복 권고 후보</h2><p className="mt-1 text-xs leading-5 text-muted-foreground">동일 서버·대상·템플릿·명령이 서로 다른 사건에서 반복된 경우 · 미해결 여부는 별도 확인</p><div className="mt-5 space-y-4">{repeats.length ? repeats.map((item, index) => <div key={`${item.host}-${index}`} className="border-b border-white/7 pb-3"><p className="text-sm font-medium">{item.label}</p><p className="mt-1 break-all text-xs text-muted-foreground">{item.host}</p><p className="mt-2 text-xs text-amber-300">사건 {item.incidents.size}건 · 권고 {item.count}개</p></div>) : <p className="text-sm text-muted-foreground">다른 사건에서 반복된 동일 조치가 없습니다.</p>}</div></section></div>
        <section className="signal-card p-5"><h2 className="font-semibold">생성·검토·적용 기록</h2><div className="mt-4 grid gap-3 sm:grid-cols-4">{[["생성된 권고", filtered.length], ["로컬 검토·제외", filtered.filter((entry) => currentReview(entry, reviews)).length], ["실행 결과 연결", stats.withExecution.length], ["검증 완료", stats.verified.length]].map(([label, value]) => <div key={String(label)} className="rounded-lg bg-white/[0.025] p-4"><p className="text-xs text-muted-foreground">{label}</p><p className="mt-2 font-mono text-2xl">{value}</p></div>)}</div><p className="mt-3 text-xs leading-5 text-muted-foreground">현재 스냅샷의 집계입니다. 시간 구간 추이나 재조사 전환율이 아니며, 기법 연결률은 방어 효과를 뜻하지 않습니다.</p></section>
      </TabsContent>
    </Tabs>
    <p role="status" aria-live="polite" className="text-sm text-cyan-200">{message}</p>
    <Dialog open={requestOpen} onOpenChange={setRequestOpen}><DialogContent className="max-h-[90dvh] overflow-y-auto"><DialogHeader><DialogTitle>적용 요청서 준비</DialogTitle><DialogDescription>현재 서버 실행기는 연결되지 않았습니다. 검토 자료와 명령·롤백·검증 절차를 JSON 요청서로 내려받아 담당자에게 전달할 수 있습니다.</DialogDescription></DialogHeader>{selected && <div className="space-y-4"><div className="rounded-xl border border-white/10 p-4"><p className="font-semibold">{selected.action.title}</p><p className="mt-2 break-all text-sm text-muted-foreground">{selected.incident.host} · {selected.action.target || "대상 확인 필요"}</p><p className="mt-2 text-xs text-muted-foreground">{selected.incident.incidentId} · {selected.action.id}</p></div><p className="text-sm leading-6 text-muted-foreground">내보내기는 승인이나 실행을 의미하지 않습니다. 현재 생성 결과와 브라우저 검토 기록이 포함됩니다.</p><Button className="w-full" onClick={exportRequest}><Download className="size-4"/>적용 요청서 내려받기</Button></div>}</DialogContent></Dialog>
  </div>;
}

function Filter({ label, value, onChange, options }: { label: string; value: string; onChange: (value: string) => void; options: string[][] }) {
  return <div className="space-y-1.5"><span className="text-xs text-muted-foreground">{label}</span><Select value={value} onValueChange={(next) => next && onChange(next)}><SelectTrigger className="w-full" aria-label={label}><SelectValue/></SelectTrigger><SelectContent><SelectItem value="all">전체</SelectItem>{options.map(([id, text]) => <SelectItem key={id} value={id}>{text}</SelectItem>)}</SelectContent></Select></div>;
}
function Metric({ label, value, note, icon: Icon }: { label: string; value: number | string; note: string; icon: typeof ShieldCheck }) {
  return <article className="signal-card flex items-start gap-3 p-4"><span className="grid size-9 shrink-0 place-items-center rounded-lg bg-cyan-400/8 text-cyan-300"><Icon aria-hidden="true" className="size-4"/></span><div><p className="text-xs text-muted-foreground">{label}</p><p className="mt-2 font-mono text-2xl font-semibold text-slate-100">{value}</p><p className="mt-1 text-xs leading-5 text-muted-foreground">{note}</p></div></article>;
}
function DetailSection({ title, icon: Icon, children }: { title: string; icon: typeof ShieldCheck; children: React.ReactNode }) {
  return <section className="border-t border-white/8 px-5 py-4"><h3 className="mb-3 flex items-center gap-2 text-sm font-semibold"><Icon aria-hidden="true" className="size-4 text-cyan-300"/>{title}</h3>{children}</section>;
}
function CountBar({ label, value, max, onClick }: { label: string; value: number; max: number; onClick?: () => void }) {
  return <div><div className="mb-2 flex justify-between gap-3 text-xs">{onClick ? <button onClick={onClick} className="font-mono text-cyan-300 underline-offset-4 hover:underline">{label}</button> : <span>{label}</span>}<span className="font-mono">{value}개</span></div><div className="h-1.5 rounded-full bg-white/5" role="img" aria-label={`${label}: ${value}개`}><div className="h-full rounded-full bg-cyan-400/75" style={{ width: `${value / max * 100}%` }}/></div></div>;
}
