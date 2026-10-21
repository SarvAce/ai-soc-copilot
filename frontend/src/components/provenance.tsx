import { useEffect } from 'react';
import { useStore } from '../store';
import type { Claim, CheckResult, Fact, QueryRecord, ValidationReport, Event } from '../types';
import { factLit, queryLit } from './lit';
import { PassBadge, Plain, PolarityBadge, Src, fmtHM, fmtTime, paramText } from './ui';

/** Hover and keyboard focus both drive provenance highlighting. */
function hoverProps(setHover: (h: ReturnType<typeof useStore>['hover']) => void,
                    h: ReturnType<typeof useStore>['hover']) {
  return {
    tabIndex: 0,
    onMouseEnter: () => setHover(h),
    onMouseLeave: () => setHover(null),
    onFocus: () => setHover(h),
    onBlur: () => setHover(null),
  };
}

export function FactTable({ facts, queries }: { facts: Fact[]; queries: QueryRecord[] }) {
  const { hover, setHover } = useStore();
  const qLabel = new Map(queries.map((q) => [q.query_id, q.label || q.query_id.slice(0, 8)]));
  return (
    <table className="grid">
      <thead>
        <tr><th>Fact</th><th>Kind</th><th>Value</th><th>Polarity <Src kind="rule" /></th><th>Events</th><th>Query</th><th>Answers</th></tr>
      </thead>
      <tbody>
        {facts.map((f) => (
          <tr key={f.fact_id} className={factLit(hover, f) ? 'lit' : hover ? 'dim' : ''}
              {...hoverProps(setHover, { kind: 'fact', id: f.fact_id })}>
            <td><b>{f.label || f.fact_id.slice(0, 8)}</b> <Src kind="tool" /></td>
            <td>{f.kind}</td>
            <td><Plain text={String(f.value)} /></td>
            <td><PolarityBadge polarity={f.polarity} /></td>
            <td>{f.event_ids.length}</td>
            <td>{qLabel.get(f.query_id) ?? f.query_id.slice(0, 8)}</td>
            <td>{f.answers.join(', ')}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export function QueryTable({ queries, facts }: { queries: QueryRecord[]; facts: Fact[] }) {
  const { hover, setHover } = useStore();
  return (
    <table className="grid">
      <thead><tr><th>Query</th><th>Tool</th><th>Parameters</th><th>Time coverage</th><th>Results</th></tr></thead>
      <tbody>
        {queries.map((q) => (
          <tr key={q.query_id} className={queryLit(hover, q.query_id, facts) ? 'lit' : hover ? 'dim' : ''}
              {...hoverProps(setHover, { kind: 'query', id: q.query_id })}>
            <td><b>{q.label || q.query_id.slice(0, 8)}</b></td>
            <td>{q.tool}</td>
            <td className="mono small">{paramText(q.params)}</td>
            <td>{q.coverage ? `${fmtHM(q.coverage.start)}–${fmtHM(q.coverage.end)} UTC${q.coverage.complete ? '' : ' ⚠ incomplete'}` : '—'}</td>
            <td>{q.result_count}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

const SECTION = { for: '▲ evidence for', against: '▼ evidence against', context: '● context' } as const;

export function ClaimList({ claims, source }: { claims: Claim[]; source: 'model' | 'template' }) {
  const { hover, setHover, factById } = useStore();
  return (
    <ol className="claims">
      {claims.map((c, i) => {
        const lit = hover?.kind === 'claim' && hover.factIds.join() === c.fact_ids.join();
        return (
          <li key={i} className={`claim claim-${c.section} ${lit ? 'lit' : ''}`}
              {...hoverProps(setHover, { kind: 'claim', factIds: c.fact_ids })}>
            <div className="claim-meta">
              <span className="sec">{SECTION[c.section]}</span>
              <Src kind="rule" detail="section" />
              <Src kind={source} />
            </div>
            <Plain text={c.text} block />
            <div className="claim-cites">cites {c.fact_ids.map((id) => (
              <span key={id} className="chip">{factById.get(id)?.label ?? id.slice(0, 8)}</span>))}
            </div>
          </li>
        );
      })}
    </ol>
  );
}

/** Every check of a gate as its own tile, with its reason string. */
export function ChecksGrid({ report, title }: { report: ValidationReport | null | undefined; title: string }) {
  const { factById } = useStore();
  if (!report) return <p className="muted">{title}: not run.</p>;
  return (
    <div>
      <div className="checks-head">
        <b>{title}</b> <Src kind="rule" detail="gate check" />
        <span className="muted"> {report.checks.filter((c) => !c.passed).length} of {report.checks.length} failed</span>
      </div>
      <div className="checks">
        {report.checks.map((c: CheckResult) => (
          <div key={c.check_id} className={`check ${c.passed ? 'check-ok' : 'check-fail'}`}>
            <div className="check-top"><b>{c.check_id}</b><PassBadge passed={c.passed} /></div>
            <Plain text={c.reason || (c.passed ? 'No issue found.' : '')} block />
            {c.gap && <div className="gap">gap <b>{c.gap.gap_type}</b>: <Plain text={c.gap.detail} /></div>}
            {c.fact_ids.length > 0 && (
              <div className="claim-cites">rejects {c.fact_ids.map((id) => (
                <span key={id} className="chip chip-bad">{factById.get(id)?.label ?? id.slice(0, 8)}</span>))}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

export function EventLine({ event }: { event: Event }) {
  return (
    <div className="event">
      <div><b>{event.event_id}</b> · {fmtTime(event.ts)} · {event.event_type}
        {event.outcome ? ` · ${event.outcome}` : ''}{event.failure_reason ? ` (${event.failure_reason})` : ''}</div>
      <div className="small muted">user <Plain text={event.user} /> · ip {event.src_ip || '—'} · {event.country || '—'}
        · device {event.device_id || '—'} · app {event.app || '—'}</div>
      {event.user_agent && <div className="small muted">user_agent (untrusted): <Plain text={event.user_agent} /></div>}
      {event.raw && <pre className="raw"><Plain text={event.raw} /></pre>}
    </div>
  );
}

/** What the hovered claim / fact / event / query traces back to. */
export function ProvenancePanel() {
  const { hover, detail, factById } = useStore();
  const facts = [...factById.values()];
  const events = detail?.events ?? {};
  const queries = detail?.queries ?? [];
  let lit: Fact[] = [];
  if (hover?.kind === 'fact' || hover?.kind === 'claim') lit = facts.filter((f) => factLit(hover, f));
  const eventIds = new Set(lit.flatMap((f) => f.event_ids));
  const queryIds = new Set(lit.map((f) => f.query_id));
  if (hover?.kind === 'event') eventIds.add(hover.id);
  if (hover?.kind === 'query') queryIds.add(hover.id);
  return (
    <aside className="prov" aria-live="polite">
      <h4>Provenance</h4>
      {!hover && <p className="muted">Hover or focus a claim, fact, query or event. A claim lights its facts; a fact lights its events and the query behind it.</p>}
      {lit.length > 0 && <p>{lit.map((f) => <span key={f.fact_id} className="chip">{f.label}</span>)}</p>}
      {[...queryIds].map((id) => {
        const q = queries.find((x) => x.query_id === id);
        return q ? (
          <div key={id} className="prov-q"><Src kind="tool" detail={q.tool} /> <b>{q.label}</b> {paramText(q.params)}<br />
            <span className="small muted">{q.coverage ? `${fmtTime(q.coverage.start)} → ${fmtTime(q.coverage.end)}` : 'no coverage'} · {q.result_count} results</span></div>
        ) : null;
      })}
      {[...eventIds].slice(0, 8).map((id) => events[id] ? <EventLine key={id} event={events[id]} /> : null)}
      {eventIds.size > 8 && <p className="muted small">+ {eventIds.size - 8} more events</p>}
    </aside>
  );
}

export function PayloadDrawer({ title, subtitle, data, onClose }: {
  title: string; subtitle?: string; data: unknown; onClose: () => void;
}) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);
  return (
    <div className="drawer" role="dialog" aria-label={title}>
      <header>
        <div><h3>{title}</h3>{subtitle && <div className="muted small">{subtitle}</div>}</div>
        <button onClick={onClose} autoFocus>Close ✕</button>
      </header>
      <pre className="json"><Plain text={JSON.stringify(data, null, 2)} /></pre>
    </div>
  );
}
