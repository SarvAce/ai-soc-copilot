import {
  createContext, useCallback, useContext, useEffect, useMemo, useRef, useState,
  type ReactNode,
} from 'react';
import { api, runCase } from './api';
import type {
  CaseDetail, Counters, Fact, Limits, NodeEvent, NodeName, ScenarioList, Stage1,
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

  // Interactive Replay & Stepping controls
  isReplaying: boolean;
  playReplay: () => void;
  pauseReplay: () => void;
  stepForward: () => void;
  stepBackward: () => void;
  restartReplay: () => void;
  jumpToStep: (index: number) => void;

  // Selected agent & pass inspection
  selectedNode: NodeName | null;
  selectedPass: number;
  selectNode: (node: NodeName | null, pass?: number) => void;
  setSelectedPass: (pass: number) => void;
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
  const [isReplaying, setIsReplaying] = useState(false);
  const [speedMs, setSpeedMs] = useState(1000);
  const [status, setStatus] = useState<RunStatus>('idle');
  const [error, setError] = useState<string | null>(null);
  const [limitsLive, setLimitsLive] = useState<Limits>(DEFAULT_LIMITS);
  const [hover, setHover] = useState<Hover>(null);

  const [selectedNode, setSelectedNode] = useState<NodeName | null>(null);
  const [selectedPass, setSelectedPass] = useState<number>(1);

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
    setIsReplaying(false);
    setLimitsLive(d.limits);
    setStatus(!d.started ? 'idle' : d.paused ? 'paused' : 'closed');
    if (d.steps.length > 0) {
      const last = d.steps[d.steps.length - 1]!;
      setSelectedNode(last.node);
      const passes = d.steps.filter((s) => s.node === last.node).length;
      setSelectedPass(passes || 1);
    } else {
      setSelectedNode('detector');
      setSelectedPass(1);
    }
  }, []);

  const refresh = useCallback(async () => {
    if (!caseId) return;
    adopt(await api.detail(scenarioId, caseId));
  }, [adopt, caseId, scenarioId]);

  // Stage 1 for the chosen scenario; an empty case list is a valid outcome.
  useEffect(() => {
    abort.current?.abort();
    setStage1(null); setCaseId(null); setDetail(null); setSteps([]);
    setRevealed(0); setIsReplaying(false); setStatus('idle'); setError(null);
    setSelectedNode('detector'); setSelectedPass(1);
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

  // Auto-advance replay when isReplaying is true and not running live
  useEffect(() => {
    if (!isReplaying || status === 'running') return;
    if (revealed >= steps.length) {
      setIsReplaying(false);
      return;
    }
    const timer = setTimeout(() => {
      setRevealed((n) => {
        const next = n + 1;
        const curStep = steps[next - 1];
        if (curStep) {
          setSelectedNode(curStep.node);
          const passNum = steps.slice(0, next).filter((s) => s.node === curStep.node).length;
          setSelectedPass(passNum || 1);
        }
        return next;
      });
    }, speedMs);
    return () => clearTimeout(timer);
  }, [isReplaying, revealed, steps, speedMs, status]);

  const start = useCallback(() => {
    if (!caseId) return;
    abort.current?.abort();
    const controller = new AbortController();
    abort.current = controller;
    setSteps([]); setRevealed(0); setIsReplaying(false); setError(null); setStatus('running');
    setSelectedNode('detector'); setSelectedPass(1);
    setDetail((d) => (d ? { ...d, started: false, report: null, paused: false, decision: null } : d));

    runCase(scenarioId, caseId, fault, faultWhen, (m) => {
      if (m.type === 'start') {
        setLimitsLive(m.limits);
      } else if (m.type === 'node') {
        setSteps((s) => {
          const next = [...s, m.event];
          setRevealed(next.length);
          setSelectedNode(m.event.node);
          const passCount = next.filter((item) => item.node === m.event.node).length;
          setSelectedPass(passCount || 1);
          return next;
        });
      } else if (m.type === 'paused') {
        setDetail(m.detail);
      } else if (m.type === 'error') {
        setError(m.message);
        setStatus('error');
      } else if (m.type === 'done') {
        setStatus((s) => (s === 'error' ? s : 'paused'));
      }
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

  const selectNode = useCallback((node: NodeName | null, pass?: number) => {
    setSelectedNode(node);
    if (node) {
      if (pass !== undefined) {
        setSelectedPass(pass);
      } else {
        // Find pass relevant to current revealed or latest
        const matched = steps.slice(0, revealed).map((s, i) => ({ s, i })).filter(({ s }) => s.node === node);
        if (matched.length > 0) {
          setSelectedPass(matched.length);
        } else {
          setSelectedPass(1);
        }
      }
    }
  }, [steps, revealed]);

  const playReplay = useCallback(() => {
    if (steps.length === 0) return;
    if (revealed >= steps.length) {
      setRevealed(1);
      const first = steps[0];
      if (first) {
        setSelectedNode(first.node);
        setSelectedPass(1);
      }
    }
    setIsReplaying(true);
  }, [steps, revealed]);

  const pauseReplay = useCallback(() => {
    setIsReplaying(false);
  }, []);

  const stepForward = useCallback(() => {
    setIsReplaying(false);
    if (revealed < steps.length) {
      const next = revealed + 1;
      setRevealed(next);
      const nextStep = steps[next - 1];
      if (nextStep) {
        setSelectedNode(nextStep.node);
        const passNum = steps.slice(0, next).filter((s) => s.node === nextStep.node).length;
        setSelectedPass(passNum || 1);
      }
    }
  }, [revealed, steps]);

  const stepBackward = useCallback(() => {
    setIsReplaying(false);
    if (revealed > 1) {
      const prev = revealed - 1;
      setRevealed(prev);
      const prevStep = steps[prev - 1];
      if (prevStep) {
        setSelectedNode(prevStep.node);
        const passNum = steps.slice(0, prev).filter((s) => s.node === prevStep.node).length;
        setSelectedPass(passNum || 1);
      }
    } else if (revealed === 1) {
      setRevealed(0);
      setSelectedNode('detector');
      setSelectedPass(1);
    }
  }, [revealed, steps]);

  const restartReplay = useCallback(() => {
    setIsReplaying(false);
    setRevealed(0);
    setSelectedNode('detector');
    setSelectedPass(1);
  }, []);

  const jumpToStep = useCallback((index: number) => {
    setIsReplaying(false);
    if (index === 0) {
      setRevealed(0);
      setSelectedNode('detector');
      setSelectedPass(1);
      return;
    }
    const targetRev = Math.min(steps.length, Math.max(1, index));
    setRevealed(targetRev);
    const targetStep = steps[targetRev - 1];
    if (targetStep) {
      setSelectedNode(targetStep.node);
      const passNum = steps.slice(0, targetRev).filter((s) => s.node === targetStep.node).length;
      setSelectedPass(passNum || 1);
    }
  }, [steps]);

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
    skipAnimation: () => { setIsReplaying(false); setRevealed(steps.length); },
    speedMs, setSpeedMs,
    status, error, limits: limitsLive, counters, start, refresh, decide,
    hover, setHover, factById,

    isReplaying, playReplay, pauseReplay, stepForward, stepBackward, restartReplay, jumpToStep,
    selectedNode, selectedPass, selectNode, setSelectedPass,
  };
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}
