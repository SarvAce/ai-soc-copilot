import type { ReactNode } from 'react';
import type { Counters, Limits, Polarity, Priority } from '../types';

/** Untrusted text (narrative, user_agent, raw log lines): always a text node.
 *  React escapes it; there is no markdown, no HTML, no dangerouslySetInnerHTML
 *  anywhere in this app (check R10). */
export function Plain({ text, block }: { text: string | undefined | null; block?: boolean }) {
  return <span className={block ? 'plain plain-block' : 'plain'}>{text ?? ''}</span>;
}

export type SourceKind = 'tool' | 'rule' | 'model' | 'template';

const SRC: Record<SourceKind, { glyph: string; word: string; hint: string }> = {
  tool: { glyph: '⚙', word: 'TOOL', hint: 'Computed by a read-only tool query' },
  rule: { glyph: '▤', word: 'RULE', hint: 'Decided by a rule table row' },
  model: { glyph: '✎', word: 'MODEL', hint: 'Written by the narrative model: wording only' },
  template: { glyph: '▣', word: 'TEMPLATE', hint: 'Written by the deterministic template' },
};

/** Who produced a value. Glyph + word + colour, never colour alone. */
export function Src({ kind, detail }: { kind: SourceKind; detail?: string }) {
  const s = SRC[kind];
  return (
    <span className={`src src-${kind}`} title={`${s.hint}${detail ? ` · ${detail}` : ''}`}>
      <span aria-hidden="true">{s.glyph}</span> {s.word}{detail ? ` · ${detail}` : ''}
    </span>
  );
}

const POL: Record<Polarity, { glyph: string; word: string }> = {
  MALICIOUS: { glyph: '▲', word: 'malicious' },
  BENIGN: { glyph: '▼', word: 'benign' },
  NEUTRAL: { glyph: '●', word: 'neutral' },
};

export function PolarityBadge({ polarity }: { polarity: Polarity }) {
  const p = POL[polarity];
  return <span className={`pol pol-${polarity.toLowerCase()}`}><span aria-hidden="true">{p.glyph}</span> {p.word}</span>;
}

export function PassBadge({ passed }: { passed: boolean }) {
  return (
    <span className={passed ? 'pass pass-ok' : 'pass pass-fail'}>
      <span aria-hidden="true">{passed ? '✓' : '✗'}</span> {passed ? 'PASS' : 'FAIL'}
    </span>
  );
}

const PRI_SHAPE: Record<Priority, string> = { P1: '▲▲▲▲', P2: '▲▲▲', P3: '▲▲', P4: '▲' };
export function PriorityBadge({ priority }: { priority: Priority }) {
  return <span className={`pri pri-${priority}`}><span aria-hidden="true">{PRI_SHAPE[priority]}</span> {priority}</span>;
}

export function DispositionBadge({ value }: { value: string }) {
  const glyph = value === 'SUSPECTED_COMPROMISE' ? '⚠' : value === 'UNRESOLVED' ? '?' : value === 'LIKELY_BENIGN' ? '✓' : '◐';
  return <span className={`disp disp-${value}`}><span aria-hidden="true">{glyph}</span> {value.replace(/_/g, ' ')}</span>;
}

export function SyntheticBanner() {
  return (
    <div className="synthetic" role="note">
      <strong>SYNTHETIC DATA</strong> · generated single-sign-on logs from the AI-SOC Copilot proof of
      concept. Not a live system, no real accounts.
    </div>
  );
}

export function Empty({ icon, title, children }: { icon: string; title: string; children?: ReactNode }) {
  return (
    <div className="empty">
      <div className="empty-icon" aria-hidden="true">{icon}</div>
      <h3>{title}</h3>
      <p>{children}</p>
    </div>
  );
}

export function Card({ title, note, children, right, className }: {
  title?: ReactNode; note?: ReactNode; children: ReactNode; right?: ReactNode; className?: string;
}) {
  return (
    <section className={`card ${className ?? ''}`}>
      {(title || right) && (
        <header className="card-head">
          <h3>{title}{note && <span className="note"> {note}</span>}</h3>
          {right}
        </header>
      )}
      {children}
    </section>
  );
}

export function fmtTime(iso: string | undefined | null): string {
  if (!iso) return '';
  return iso.replace('T', ' ').replace(/(\.\d+)?(\+00:00|Z)$/, '') + ' UTC';
}
export function fmtHM(iso: string | undefined | null): string {
  return iso ? iso.slice(11, 16) : '';
}

export function paramText(params: Record<string, unknown>): string {
  return Object.entries(params)
    .filter(([k]) => k !== 'topic')
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${k}=${typeof v === 'object' ? JSON.stringify(v) : String(v)}`)
    .join(', ');
}

/** One bounded budget drawn as discrete cells: consumed vs. remaining. */
function Budget({ label, used, max, hint }: { label: string; used: number; max: number; hint: string }) {
  const full = used >= max;
  return (
    <div className={`budget ${full ? 'budget-full' : ''}`} title={hint}
         role="meter" aria-label={label} aria-valuemin={0} aria-valuemax={max} aria-valuenow={used}>
      <div className="budget-top">
        <span className="budget-label">{label}</span>
        <span className="budget-num">{used}<span className="budget-max"> / {max}</span></span>
      </div>
      <div className="budget-cells" aria-hidden="true">
        {Array.from({ length: max }, (_, i) => (
          <span key={i} className={i < used ? 'cell cell-used' : 'cell'} />
        ))}
      </div>
    </div>
  );
}

/** The three hard termination guarantees, always on screen. */
export function CounterBar({ counters, limits }: { counters: Counters; limits: Limits }) {
  return (
    <div className="counters" aria-label="Termination budgets">
      <Budget label="node executions" used={counters.node_executions} max={limits.node_executions}
              hint="Completed node executions, hard bound (spec §14.5)" />
      <Budget label="evidence_retries" used={counters.evidence_retries} max={limits.evidence_retries}
              hint="Re-plans taken against the cap" />
      <Budget label="report_retries" used={counters.report_retries} max={limits.report_retries}
              hint="Redrafts taken; after this the template runs once" />
      <div className={counters.used_template ? 'tmpl tmpl-on' : 'tmpl'}>
        <span className="budget-label">used_template</span>
        <span className="budget-num">{counters.used_template ? '■ yes' : '□ no'}</span>
      </div>
    </div>
  );
}
