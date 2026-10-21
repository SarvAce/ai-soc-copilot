import type { Gap, NodeEvent, NodeName } from './types';
import type { SourceKind } from './components/ui';

export const NODES: NodeName[] = [
  'planner', 'investigator', 'evidence_gate', 'reporter', 'report_gate', 'analyst_review', 'finalize',
];

export interface NodeMeta {
  n: number;
  title: string;
  role: string;
  input: string;
  output: string;
  /** Who is responsible for what this node writes. */
  source: SourceKind | 'human';
  sourceNote: string;
}

export const META: Record<NodeName, NodeMeta> = {
  planner: {
    n: 1, title: 'Planner', role: 'Chooses which checks to run',
    input: 'case · hypotheses · open gaps', output: 'plan: ToolCall[]',
    source: 'rule', sourceNote: 'checklist rule table picks tools T1–T10',
  },
  investigator: {
    n: 2, title: 'Investigator', role: 'Runs the read-only tools',
    input: 'plan: ToolCall[]', output: 'queries · facts · timeline · discoveries',
    source: 'tool', sourceNote: 'every fact is computed by a tool query',
  },
  evidence_gate: {
    n: 3, title: 'Evidence Gate', role: 'Checks E1–E7 on the facts',
    input: 'facts · queries', output: 'evidence_check · gaps · route',
    source: 'rule', sourceNote: 'seven deterministic checks',
  },
  reporter: {
    n: 4, title: 'Reporter', role: 'Rules set the verdict; model writes words',
    input: 'facts · redraft errors', output: 'report: Report',
    source: 'model', sourceNote: 'verdict by rule table · only summary and claims by the model',
  },
  report_gate: {
    n: 5, title: 'Report Gate', role: 'Checks R1–R10 on the draft',
    input: 'report: Report', output: 'report_check · route',
    source: 'rule', sourceNote: 'ten deterministic checks',
  },
  analyst_review: {
    n: 6, title: 'Analyst review', role: 'A person decides',
    input: 'report · gate result', output: 'decision: AnalystDecision',
    source: 'human', sourceNote: 'Approve, Override (reason required) or Escalate',
  },
  finalize: {
    n: 7, title: 'Finalize', role: 'Writes the case record',
    input: 'decision', output: 'case record · audit entry · status',
    source: 'rule', sourceNote: 'CLOSED or ESCALATED',
  },
};

export type NodeState = 'idle' | 'done' | 'current' | 'waiting';

export interface EdgeInfo {
  id: string;
  source: string;
  target: string;
  /** How many times this edge was walked in the revealed part of the run. */
  count: number;
  label: string;
  payloadTitle: string;
  payload: unknown;
  loop: boolean;
  /** The edge the work just moved along (animated). */
  active: boolean;
  /** Walked at least once. */
  taken: boolean;
  /** Decision on the latest walk. */
  decision: string;
}

/** The static shape of the compiled graph (graph/build.py), for idle edges. */
export const EDGE_DEFS: { source: string; target: string; loop: boolean; idle: string }[] = [
  { source: 'planner', target: 'investigator', loop: false, idle: 'plan' },
  { source: 'investigator', target: 'evidence_gate', loop: false, idle: 'queries · facts' },
  { source: 'evidence_gate', target: 'planner', loop: true, idle: 're-plan' },
  { source: 'evidence_gate', target: 'reporter', loop: false, idle: 'route' },
  { source: 'reporter', target: 'report_gate', loop: false, idle: 'report' },
  { source: 'report_gate', target: 'reporter', loop: true, idle: 'redraft / template' },
  { source: 'report_gate', target: 'analyst_review', loop: false, idle: 'route' },
  { source: 'analyst_review', target: 'finalize', loop: false, idle: 'decision' },
  { source: 'finalize', target: '__end__', loop: false, idle: 'case record' },
];

export const edgeId = (s: string, t: string) => `${s}>${t}`;

const failedIds = (step: NodeEvent): string[] => {
  const report = step.produced.evidence_check ?? step.produced.report_check;
  return report ? report.checks.filter((c) => !c.passed).map((c) => c.check_id) : [];
};

const uniqueGapTypes = (gaps: Gap[]): string[] => [...new Set(gaps.map((g) => g.gap_type))];

/** What travels from `step` to whatever runs next. Only formats backend data. */
function carried(steps: NodeEvent[], i: number): { label: string; title: string; payload: unknown } {
  const step = steps[i]!;
  const p = step.produced;
  switch (step.node) {
    case 'planner':
      return { label: `${p.plan?.length ?? 0} tool calls`, title: 'plan: ToolCall[]', payload: { plan: p.plan } };
    case 'investigator': {
      const total = steps.slice(0, i + 1).reduce((n, s) => n + (s.produced.facts?.length ?? 0), 0);
      return {
        label: `${p.queries?.length ?? 0} queries · ${p.facts?.length ?? 0} new facts (${total} total)`,
        title: 'queries · facts · timeline · discoveries',
        payload: { queries: p.queries, facts: p.facts, merged_facts: p.merged_facts, timeline: p.timeline, discoveries: p.discoveries },
      };
    }
    case 'evidence_gate': {
      const check = p.evidence_check;
      if (step.decision === 're-plan') {
        const types = uniqueGapTypes(check?.gaps ?? []);
        return {
          label: `gap: ${types.join(', ') || 're-plan'}`,
          title: 'evidence_check (failed E-checks) · gaps: Gap[]',
          payload: {
            evidence_retries: step.counters.evidence_retries,
            failed_checks: check?.checks.filter((c) => !c.passed),
            gaps: check?.gaps,
          },
        };
      }
      return {
        label: `route: ${step.route || step.decision}`,
        title: 'route only',
        payload: { route: step.route, decision: step.decision, reason: step.reason, gaps_left_open: check?.gaps },
      };
    }
    case 'reporter':
      return {
        label: `draft · ${p.report?.claims.length ?? 0} claims · ${p.report?.model_used ?? ''}`,
        title: 'report: Report', payload: { report: p.report },
      };
    case 'report_gate': {
      const check = p.report_check;
      if (step.decision === 'redraft') {
        return {
          label: `redraft · ${failedIds(step).join(', ')} failed`,
          title: 'report_check → error list handed back to the Reporter',
          payload: {
            report_retries: step.counters.report_retries,
            error_list: check?.checks.filter((c) => !c.passed).map((c) => `${c.check_id}: ${c.reason}`),
          },
        };
      }
      if (step.decision === 'template') {
        return { label: 'template · runs once', title: 'route only',
                 payload: { route: step.route, used_template: true, reason: step.reason } };
      }
      return { label: `route: ${step.decision} · releasable`, title: 'route only',
               payload: { route: step.route, decision: step.decision, reason: step.reason } };
    }
    case 'analyst_review':
      return { label: `decision: ${p.decision?.action ?? ''}`, title: 'decision: AnalystDecision', payload: { decision: p.decision } };
    case 'finalize':
      return { label: `status: ${p.status ?? ''}`, title: 'case record · final audit entry',
               payload: { status: p.status, audit_entry: step.entry } };
  }
}

/** Edges of the run so far. `paused` means the graph waits at the interrupt. */
export function deriveEdges(steps: NodeEvent[], revealed: number, settled: boolean, paused: boolean): EdgeInfo[] {
  const shown = steps.slice(0, revealed);
  const byId = new Map<string, EdgeInfo>();
  for (const def of EDGE_DEFS) {
    byId.set(edgeId(def.source, def.target), {
      id: edgeId(def.source, def.target), source: def.source, target: def.target,
      count: 0, label: def.idle, payloadTitle: '', payload: null, loop: def.loop,
      active: false, taken: false, decision: '',
    });
  }
  const walk = (i: number, target: string, active: boolean) => {
    const step = shown[i]!;
    const edge = byId.get(edgeId(step.node, target));
    if (!edge) return;
    const c = carried(shown, i);
    edge.count += 1; edge.taken = true; edge.label = c.label;
    edge.payloadTitle = c.title; edge.payload = c.payload; edge.decision = step.decision;
    edge.active = active;
  };
  for (let i = 0; i + 1 < shown.length; i++) {
    walk(i, shown[i + 1]!.node, !settled && i + 2 === shown.length);
  }
  const last = shown[shown.length - 1];
  if (last) {
    if (last.node === 'finalize') walk(shown.length - 1, '__end__', false);
    else if (last.node === 'report_gate' && paused && revealed === steps.length
             && ['pass', 'flagged'].includes(last.decision)) {
      walk(shown.length - 1, 'analyst_review', false);
    }
  }
  return [...byId.values()];
}

export function nodeState(node: NodeName, shown: NodeEvent[], settled: boolean, paused: boolean): NodeState {
  const last = shown[shown.length - 1];
  if (node === 'analyst_review' && paused && settled && last?.node === 'report_gate'
      && ['pass', 'flagged'].includes(last.decision)) return 'waiting';
  if (last && last.node === node && !settled) return 'current';
  return shown.some((s) => s.node === node) ? 'done' : 'idle';
}

export interface LoopNote {
  kind: 're-plan' | 'redraft' | 'template';
  atIndex: number;
  title: string;
  detail: string;
}

/** The loops taken so far, read off the gates' decisions. */
export function loopsTaken(shown: NodeEvent[]): LoopNote[] {
  const notes: LoopNote[] = [];
  shown.forEach((s, i) => {
    if (s.node === 'evidence_gate' && s.decision === 're-plan') {
      const gaps = s.produced.evidence_check?.gaps ?? [];
      notes.push({
        kind: 're-plan', atIndex: i, title: 'RE-PLAN',
        detail: `Evidence Gate sent the case back to the Planner · gap ${uniqueGapTypes(gaps).join(', ')} · evidence_retries ${s.counters.evidence_retries}`,
      });
    } else if (s.node === 'report_gate' && s.decision === 'redraft') {
      notes.push({
        kind: 'redraft', atIndex: i, title: 'REDRAFT',
        detail: `Report Gate rejected the draft (${failedIds(s).join(', ')}) · report_retries ${s.counters.report_retries}`,
      });
    } else if (s.node === 'report_gate' && s.decision === 'template') {
      notes.push({
        kind: 'template', atIndex: i, title: 'TEMPLATE',
        detail: 'Report Gate switched to the deterministic template, which runs once',
      });
    }
  });
  return notes;
}
