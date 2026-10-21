import type { ReactNode } from 'react';
import { META, type NodeState } from '../pipeline';
import { useStore } from '../store';
import type { Fact, NodeEvent, NodeName, Polarity, ValidationReport } from '../types';
import { ChecksGrid, ClaimList, FactTable, QueryTable } from './provenance';
import {
  DispositionBadge, Plain, PriorityBadge, Src, paramText, type SourceKind,
} from './ui';

// ---------------------------------------------------------------- shared bits

export function SourceFor({ node, step }: { node: NodeName; step?: NodeEvent }) {
  const m = META[node];
  if (m.source === 'human') return <span className="src src-human"><span aria-hidden="true">☻</span> HUMAN</span>;
  if (node === 'reporter') {
    const kind: SourceKind = step && step.decision !== 'draft' ? 'template' : 'model';
    return <><Src kind="rule" detail="verdict" /> <Src kind={kind} detail="words" /></>;
  }
  return <Src kind={m.source} />;
}

/** Mini strip: every check of a gate as a small tile (shape + id, not colour alone). */
export function CheckStrip({ report }: { report: ValidationReport | undefined }) {
  if (!report) return null;
  return (
    <div className="strip" role="list">
      {report.checks.map((c) => (
        <span key={c.check_id} role="listitem" title={`${c.check_id}: ${c.reason}`}
              className={c.passed ? 'tile tile-ok' : 'tile tile-fail'}>
          {c.check_id} <span aria-hidden="true">{c.passed ? '✓' : '✗'}</span>
          <span className="sr">{c.passed ? 'passed' : 'failed'}</span>
        </span>
      ))}
    </div>
  );
}

const POLS: Polarity[] = ['MALICIOUS', 'BENIGN', 'NEUTRAL'];
const GLYPH: Record<Polarity, string> = { MALICIOUS: '▲', BENIGN: '▼', NEUTRAL: '●' };

export function PolarityBar({ facts }: { facts: Fact[] }) {
  const total = facts.length || 1;
  return (
    <div>
      <div className="pbar" aria-hidden="true">
        {POLS.map((p) => {
          const n = facts.filter((f) => f.polarity === p).length;
          return n ? <span key={p} className={`pbar-seg pol-${p.toLowerCase()}`} style={{ width: `${(n / total) * 100}%` }} /> : null;
        })}
      </div>
      <div className="small">
        {POLS.map((p) => (
          <span key={p} className={`pol pol-${p.toLowerCase()}`} style={{ marginRight: 10 }}>
            {GLYPH[p]} {facts.filter((f) => f.polarity === p).length} {p.toLowerCase()}
          </span>
        ))}
      </div>
    </div>
  );
}

function ToolChips({ step }: { step: NodeEvent }) {
  return (
    <div className="chips">
      {(step.produced.plan ?? []).map((c, i) => (
        <span key={i} className="chip chip-tool" title={`${paramText(c.params)} → ${c.answers.join(', ')}`}>{c.tool}</span>
      ))}
    </div>
  );
}

// -------------------------------------------------------- step cards (compact)

interface CardProps { execs: NodeEvent[]; state: NodeState }

function Shell({ node, state, execs, children, index }: {
  node: NodeName; state: NodeState; execs: NodeEvent[]; children: ReactNode; index?: number;
}) {
  const m = META[node];
  return (
    <article className={`stepcard state-${state}`} style={{ animationDelay: `${(index ?? 0) * 140}ms` }}
             aria-label={`Step ${m.n}: ${m.title}`}>
      <header className="stepcard-head">
        <span className="stepcard-n" aria-hidden="true">{m.n}</span>
        <div className="stepcard-title">
          <h3>{m.title}</h3>
          <div className="muted small">{m.role}</div>
        </div>
        <div className="stepcard-state">
          <span className={`runs ${execs.length ? 'runs-on' : ''}`}>
            {execs.length ? `ran ×${execs.length}` : 'not run'}
          </span>
          {state === 'waiting' && <span className="runs runs-wait">⏸ waiting for analyst</span>}
        </div>
      </header>
      <div className="io">
        <div><span className="io-k">IN</span> <code>{m.input}</code></div>
        <div><span className="io-k">OUT</span> <code>{m.output}</code></div>
      </div>
      <div className="stepcard-src"><SourceFor node={node} step={execs[0]} /> <span className="muted small">{m.sourceNote}</span></div>
      <div className="stepcard-body">{children}</div>
    </article>
  );
}

function Exec({ step, execs, children }: { step: NodeEvent; execs: NodeEvent[]; children: ReactNode }) {
  const k = execs.indexOf(step) + 1;
  return (
    <div className="exec">
      {execs.length > 1 && <div className="exec-k">execution {k} · seq {step.seq}</div>}
      <div className="exec-decision"><b>{step.decision}</b> <span className="muted small"><Plain text={step.reason} /></span></div>
      {children}
    </div>
  );
}

export function DetectorStep({ execs, state, index }: CardProps & { index?: number }) {
  const { stage1, caseId } = useStore();
  const kase = stage1?.cases.find((c) => c.case_id === caseId) ?? stage1?.cases[0];
  return (
    <Shell node="detector" state={state} execs={execs} index={index}>
      <div className="small">
        <b>Stage 1 Detection:</b> {kase ? `${kase.rule} opened ${kase.case_id} (${kase.hypothesis})` : 'No case opened'}
      </div>
      {kase && (
        <div className="chips">
          <span className="chip chip-ok">{kase.rule}</span>
          <span className="chip">{kase.hypothesis}</span>
          <span className="chip">{kase.users.length} user(s)</span>
          <span className="chip">{kase.src_ips.join(', ')}</span>
        </div>
      )}
    </Shell>
  );
}

export function PlannerStep({ execs, state, index }: CardProps & { index?: number }) {
  return (
    <Shell node="planner" state={state} execs={execs} index={index}>
      {execs.length === 0 && <p className="muted small">Waiting to be reached.</p>}
      {execs.map((s) => (
        <Exec key={s.seq} step={s} execs={execs}>
          {(s.received.gaps?.length ?? 0) > 0 && (
            <div className="small">asked by gap {s.received.gaps!.map((g) => <b key={g.gap_type + g.detail}>{g.gap_type} </b>)}</div>
          )}
          <div className="small">{s.produced.plan?.length ?? 0} tool calls</div>
          <ToolChips step={s} />
        </Exec>
      ))}
    </Shell>
  );
}

export function InvestigatorStep({ execs, state, index }: CardProps & { index?: number }) {
  return (
    <Shell node="investigator" state={state} execs={execs} index={index}>
      {execs.length === 0 && <p className="muted small">Waiting to be reached.</p>}
      {execs.map((s) => (
        <Exec key={s.seq} step={s} execs={execs}>
          <div className="small">{s.produced.queries?.length ?? 0} queries · {s.produced.facts?.length ?? 0} new facts
            {(s.produced.merged_facts?.length ?? 0) > 0 && ` · ${s.produced.merged_facts!.length} merged`}
            {(s.produced.discoveries?.length ?? 0) > 0 && ` · ${s.produced.discoveries!.length} discoveries`}</div>
          <PolarityBar facts={s.produced.facts ?? []} />
        </Exec>
      ))}
    </Shell>
  );
}

export function EvidenceGateStep({ execs, state, index }: CardProps & { index?: number }) {
  return (
    <Shell node="evidence_gate" state={state} execs={execs} index={index}>
      {execs.length === 0 && <p className="muted small">Waiting to be reached.</p>}
      {execs.map((s) => (
        <Exec key={s.seq} step={s} execs={execs}>
          <CheckStrip report={s.produced.evidence_check} />
          <div className="small">{s.decision === 're-plan' ? '↺ loops back to the Planner' : `→ ${s.route || s.decision}`}</div>
        </Exec>
      ))}
    </Shell>
  );
}

export function ReporterStep({ execs, state, index }: CardProps & { index?: number }) {
  return (
    <Shell node="reporter" state={state} execs={execs} index={index}>
      {execs.length === 0 && <p className="muted small">Waiting to be reached.</p>}
      {execs.map((s) => {
        const r = s.produced.report;
        return (
          <Exec key={s.seq} step={s} execs={execs}>
            {r && <div className="chips"><DispositionBadge value={r.verdict.disposition} /><PriorityBadge priority={r.verdict.priority} />
              <span className="chip">row {r.verdict.row}</span></div>}
            <div className="small">{r?.claims.length ?? 0} claims · written by {r?.model_used}</div>
            {(s.received.errors?.length ?? 0) > 0 && <div className="small bad">redraft: {s.received.errors!.length} errors handed back</div>}
          </Exec>
        );
      })}
    </Shell>
  );
}

export function ReportGateStep({ execs, state, index }: CardProps & { index?: number }) {
  return (
    <Shell node="report_gate" state={state} execs={execs} index={index}>
      {execs.length === 0 && <p className="muted small">Waiting to be reached.</p>}
      {execs.map((s) => (
        <Exec key={s.seq} step={s} execs={execs}>
          <CheckStrip report={s.produced.report_check} />
          <div className="small">{s.decision === 'redraft' ? '↺ draft rejected, back to the Reporter' : s.decision === 'template' ? '↺ template runs once' : `→ ${s.decision}`}</div>
        </Exec>
      ))}
    </Shell>
  );
}

export function AnalystReviewStep({ execs, state, index }: CardProps & { index?: number }) {
  return (
    <Shell node="analyst_review" state={state} execs={execs} index={index}>
      {execs.length === 0 && <p className="muted small">{state === 'waiting' ? 'The graph is paused here.' : 'Waiting to be reached.'}</p>}
      {execs.map((s) => (
        <Exec key={s.seq} step={s} execs={execs}>
          <div className="chips"><span className="chip">{s.produced.decision?.action}</span><span className="chip">by {s.produced.decision?.analyst}</span></div>
          {s.produced.decision?.reason && <div className="small"><Plain text={s.produced.decision.reason} /></div>}
        </Exec>
      ))}
    </Shell>
  );
}

export function FinalizeStep({ execs, state, index }: CardProps & { index?: number }) {
  return (
    <Shell node="finalize" state={state} execs={execs} index={index}>
      {execs.length === 0 && <p className="muted small">Waiting to be reached.</p>}
      {execs.map((s) => (
        <Exec key={s.seq} step={s} execs={execs}>
          <div className="chips"><span className={`chip ${s.produced.status === 'CLOSED' ? 'chip-ok' : 'chip-bad'}`}>{s.produced.status}</span></div>
        </Exec>
      ))}
    </Shell>
  );
}

export const STEP_COMPONENTS = {
  detector: DetectorStep,
  planner: PlannerStep, investigator: InvestigatorStep, evidence_gate: EvidenceGateStep,
  reporter: ReporterStep, report_gate: ReportGateStep, analyst_review: AnalystReviewStep,
  finalize: FinalizeStep,
} as const;

// -------------------------------------------------- full execution inspector

export function AuditBlock({ step }: { step: NodeEvent }) {
  const e = step.entry;
  if (!e) return null;
  return (
    <div className="audit">
      <div className="small muted">Audit entry · hash-chained</div>
      <code>seq {e.seq} · {e.node} · {e.decision}</code>
      <code>output_hash {e.output_hash}</code>
      <code>prev_hash&nbsp;&nbsp; {e.prev_hash || '(first)'}</code>
      <code>entry_hash&nbsp; {e.entry_hash}</code>
    </div>
  );
}

/** Everything one node execution received and produced. */
export function ExecutionDetail({ step }: { step: NodeEvent }) {
  const { detail, factById } = useStore();
  const queries = detail?.queries ?? step.produced.queries ?? [];
  const allFacts = [...factById.values()];
  const p = step.produced;
  return (
    <div className="detail">
      <h3>
        Step {step.seq} · {META[step.node].title} <SourceFor node={step.node} step={step} />
      </h3>
      <p><b>{step.decision}</b> — <Plain text={step.reason} /></p>

      {step.node === 'planner' && (<>
        <h4>Received</h4>
        <p className="small">hypotheses {step.received.hypotheses?.join(', ')}</p>
        {(step.received.gaps?.length ?? 0) === 0
          ? <p className="small muted">No open gap: first pass.</p>
          : step.received.gaps!.map((g, i) => <p key={i} className="small"><b>{g.gap_type}</b>: <Plain text={g.detail} /></p>)}
        <h4>Produced · plan <Src kind="rule" /></h4>
        <table className="grid"><thead><tr><th>Tool</th><th>Parameters</th><th>Answers</th></tr></thead>
          <tbody>{(p.plan ?? []).map((c, i) => (
            <tr key={i}><td><b>{c.tool}</b></td><td className="mono small">{paramText(c.params)}</td><td>{c.answers.join(', ')}</td></tr>))}</tbody></table>
      </>)}

      {step.node === 'investigator' && (<>
        <h4>Received · {step.received.plan?.length ?? 0} planned checks</h4>
        <h4>Produced · queries</h4>
        <QueryTable queries={p.queries ?? []} facts={allFacts} />
        <h4>Produced · facts</h4>
        <PolarityBar facts={p.facts ?? []} />
        <FactTable facts={p.facts ?? []} queries={queries.length ? queries : (p.queries ?? [])} />
        {(p.merged_facts?.length ?? 0) > 0 && (<>
          <h4>Recomputed onto an existing hash (merged, not duplicated)</h4>
          <FactTable facts={p.merged_facts!} queries={queries} />
        </>)}
        {(p.discoveries?.length ?? 0) > 0 && (<>
          <h4>Discoveries</h4>
          <ul>{p.discoveries!.map((d, i) => <li key={i}>{d.kind}: <Plain text={d.user || d.src_ip} /> (pass {d.found_in_pass})</li>)}</ul>
        </>)}
        {(p.timeline?.length ?? 0) > 0 && <p className="small muted">{p.timeline!.length} timeline lines added</p>}
      </>)}

      {step.node === 'evidence_gate' && (<>
        <p className="small">Received {step.received.fact_count} facts from {step.received.query_count} queries.</p>
        <ChecksGrid report={p.evidence_check} title="Evidence Gate · E1–E7" />
        {(p.evidence_check?.gaps.length ?? 0) > 0 && (<>
          <h4>Typed gaps</h4>
          <ul>{p.evidence_check!.gaps.map((g, i) => <li key={i}><b>{g.gap_type}</b>: <Plain text={g.detail} /></li>)}</ul>
        </>)}
        <p className="route">route → <b>{step.route || '—'}</b> ({step.decision})</p>
      </>)}

      {step.node === 'reporter' && p.report && (<>
        {(step.received.errors?.length ?? 0) > 0 && (<>
          <h4>Received · error list from the Report Gate</h4>
          <ul className="bad">{step.received.errors!.map((e, i) => <li key={i}><Plain text={e} /></li>)}</ul>
        </>)}
        <h4>Verdict <Src kind="rule" detail={`Table 28 row ${p.report.verdict.row}`} /></h4>
        <div className="chips">
          <DispositionBadge value={p.report.verdict.disposition} />
          <PriorityBadge priority={p.report.verdict.priority} />
          <span className="chip">impact {p.report.verdict.impact}</span>
        </div>
        <p className="small"><Plain text={p.report.verdict.reason} /></p>
        <h4>Narrative <Src kind={step.decision === 'draft' ? 'model' : 'template'} detail={p.report.model_used} /> <span className="muted small">plain text only</span></h4>
        <Plain text={p.report.summary} block />
        <ClaimList claims={p.report.claims} source={step.decision === 'draft' ? 'model' : 'template'} />
      </>)}

      {step.node === 'report_gate' && (<>
        <ChecksGrid report={p.report_check} title="Report Gate · R1–R10" />
        <p className="route">route → <b>{step.route || '—'}</b> ({step.decision})</p>
      </>)}

      {step.node === 'analyst_review' && (
        <p>Decision <b>{p.decision?.action}</b> by {p.decision?.analyst}. <Plain text={p.decision?.reason} /></p>
      )}
      {step.node === 'finalize' && <p>Case status <b>{p.status}</b>.</p>}

      <AuditBlock step={step} />
    </div>
  );
}
