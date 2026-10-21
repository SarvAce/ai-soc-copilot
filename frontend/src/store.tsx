import {
  createContext, useCallback, useContext, useEffect, useMemo, useRef, useState,
  type ReactNode,
} from 'react';
import { api, runCase } from './api';
import type {
  CaseDetail, Counters, Fact, Limits, NodeEvent, ScenarioList, Stage1,
} from './types';

export type Page = 'queue' | 'flow' | 'case' | 'review' | 'evaluation' | 'architecture';
export type RunStatus = 'idle' | 'running' | 'paused' | 'closed' | 'error';

/** What is currently hovered, for provenance highlighting. */
export type Hover =
  | { kind: 'fact'; id: string }
  | { kind: 'claim'; factIds: string[] }
  | { kind: 'event'; id: string }
  | { kind: 'query'; id: string }
  | null;

interface Store {
  page: Page; setPage: (p: Page) => void;
  theme: 'dark' | 'light'; toggleTheme: () => void;
  scenarios: ScenarioList | null;
  scenarioId: string; setScenarioId: (s: string) => void;
  stage1: Stage1 | null;
  caseId: string | null; setCaseId: (c: string) => void;
  fault: string; setFault: (f: string) => void;
  faultWhen: 'first' | 'always'; setFaultWhen: (f: 'first' | 'always') => void;
  detail: CaseDetail | null;
  steps: NodeEvent[];
  revealed: number;
  skipAnimation: () => void;
  speedMs: number; setSpeedMs: (n: number) => void;
  status: RunStatus;
  error: string | null;
  limits: Limits;
  counters: Counters;
  start: () => void;
  refresh: () => Promise<void>;
  decide: (action: 'Approve' | 'Override' | 'Escalate', reason: string, analyst: string) => Promise<void>;
  hover: Hover; setHover: (h: Hover) => void;
  factById: Map<string, Fact>;
}

const Ctx = createContext<Store | null>(null);

export function useStore(): Store {
  const value = useContext(Ctx);
  if (!value) throw new Error('StoreProvider missing');
  return value;
}

const DEFAULT_LIMITS: Limits = { node_executions: 17, evidence_retries: 2, report_retries: 1 };
const ZERO: Counters = { node_executions: 0, evidence_retries: 0, report_retries: 0, used_template: false };

export function StoreProvider({ children }: { children: ReactNode }) {
  const [page, setPage] = useState<Page>('flow');
  const [theme, setTheme] = useState<'dark' | 'light'>(
    () => (localStorage.getItem('theme') as 'dark' | 'light' | null) ?? 'dark');
  const [scenarios, setScenarios] = useState<ScenarioList | null>(null);
  const [scenarioId, setScenarioIdRaw] = useState('S2');
  const [stage1, setStage1] = useState<Stage1 | null>(null);
  const [caseId, setCaseId] = useState<string | null>(null);
  const [fault, setFault] = useState('off');
  const [faultWhen, setFaultWhen] = useState<'first' | 'always'>('first');
  const [detail, setDetail] = useState<CaseDetail | null>(null);
  const [steps, setSteps] = useState<NodeEvent[]>([]);
  const [revealed, setRevealed] = useState(0);
  const [speedMs, setSpeedMs] = useState(1100);
  const [status, setStatus] = useState<RunStatus>('idle');
  const [error, setError] = useState<string | null>(null);
  const [limitsLive, setLimitsLive] = useState<Limits>(DEFAULT_LIMITS);
  const [hover, setHover] = useState<Hover>(null);
  const abort = useRef<AbortController | null>(null);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem('theme', theme);
  }, [theme]);

  useEffect(() => {
    api.scenarios().then(setScenarios).catch((e: Error) => setError(e.message));
  }, []);

  const adopt = useCallback((d: CaseDetail) => {
    setDetail(d);
    setSteps(d.steps);
    setRevealed(d.steps.length);
    setLimitsLive(d.limits);
    setStatus(!d.started ? 'idle' : d.paused ? 'paused' : 'closed');
  }, []);

  const refresh = useCallback(async () => {
    if (!caseId) return;
    adopt(await api.detail(scenarioId, caseId));
  }, [adopt, caseId, scenarioId]);

  // Stage 1 for the chosen scenario; an empty case list is a valid outcome.
  useEffect(() => {
    abort.current?.abort();
    setStage1(null); setCaseId(null); setDetail(null); setSteps([]);
    setRevealed(0); setStatus('idle'); setError(null);
    api.stage1(scenarioId).then((s) => {
      setStage1(s);
      setCaseId(s.cases[0]?.case_id ?? null);
    }).catch((e: Error) => setError(e.message));
  }, [scenarioId]);

  useEffect(() => {
    if (!caseId) return;
    abort.current?.abort();
    api.detail(scenarioId, caseId).then(adopt).catch((e: Error) => setError(e.message));
  }, [scenarioId, caseId, adopt]);

  // Reveal one step at a time so the viewer can follow the work moving.
  useEffect(() => {
    if (revealed >= steps.length) return;
    const timer = setTimeout(() => setRevealed((n) => n + 1), speedMs);
    return () => clearTimeout(timer);
  }, [revealed, steps.length, speedMs]);

  const start = useCallback(() => {
    if (!caseId) return;
    abort.current?.abort();
    const controller = new AbortController();
    abort.current = controller;
    setSteps([]); setRevealed(0); setError(null); setStatus('running');
    setDetail((d) => (d ? { ...d, started: false, report: null, paused: false, decision: null } : d));
    runCase(scenarioId, caseId, fault, faultWhen, (m) => {
      if (m.type === 'start') setLimitsLive(m.limits);
      else if (m.type === 'node') setSteps((s) => [...s, m.event]);
      else if (m.type === 'paused') setDetail(m.detail);
      else if (m.type === 'error') { setError(m.message); setStatus('error'); }
      else if (m.type === 'done') setStatus((s) => (s === 'error' ? s : 'paused'));
    }, controller.signal).catch((e: Error) => {
      if (e.name !== 'AbortError') { setError(e.message); setStatus('error'); }
    });
  }, [caseId, fault, faultWhen, scenarioId]);

  const decide = useCallback(async (
    action: 'Approve' | 'Override' | 'Escalate', reason: string, analyst: string,
  ) => {
    if (!caseId) return;
    adopt(await api.decide(scenarioId, caseId, { action, reason, analyst }));
  }, [adopt, caseId, scenarioId]);

  const counters = useMemo(
    () => (revealed > 0 ? steps[revealed - 1]?.counters ?? ZERO : ZERO), [steps, revealed]);

  const factById = useMemo(() => {
    const map = new Map<string, Fact>();
    for (const fact of detail?.facts ?? []) map.set(fact.fact_id, fact);
    for (const step of steps) {
      for (const fact of [...(step.produced.facts ?? []), ...(step.produced.merged_facts ?? [])]) {
        map.set(fact.fact_id, fact);
      }
    }
    return map;
  }, [detail, steps]);

  const value: Store = {
    page, setPage, theme, toggleTheme: () => setTheme((t) => (t === 'dark' ? 'light' : 'dark')),
    scenarios, scenarioId, setScenarioId: setScenarioIdRaw, stage1, caseId, setCaseId,
    fault, setFault, faultWhen, setFaultWhen, detail, steps, revealed,
    skipAnimation: () => setRevealed(steps.length), speedMs, setSpeedMs,
    status, error, limits: limitsLive, counters, start, refresh, decide,
    hover, setHover, factById,
  };
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}
