import { useEffect, useState } from 'react';
import { api } from '../api';
import { Card, Empty, Plain, SyntheticBanner } from '../components/ui';
import type { EvaluationResult, FaultDetail, SweepResult } from '../types';

const VERDICT: Record<string, string> = { met: '✓ met', MISSED: '✗ MISSED', reported: '● reported' };

function Confusion({ rows }: { rows: string[][] }) {
  if (rows.length <= 1) return <p className="muted">No account verdict was produced on this run.</p>;
  const [head, ...body] = rows as [string[], ...string[][]];
  const nums = body.flatMap((r) => r.slice(1).map((c) => Number(c)).filter((n) => !Number.isNaN(n)));
  const max = Math.max(1, ...nums);
  return (
    <>
      <table className="grid confusion">
        <thead><tr>{head.map((h, i) => <th key={i}>{i === 0 ? 'expected ↓ / produced →' : h}</th>)}</tr></thead>
        <tbody>{body.map((r, i) => (
          <tr key={i}>{r.map((c, j) => {
            const n = Number(c);
            const diag = j > 0 && head[j] === r[0];
            return j === 0 ? <th key={j}>{c}</th> : (
              <td key={j} className={Number.isNaN(n) ? '' : diag ? 'cm-diag' : n > 0 ? 'cm-miss' : ''}
                  style={Number.isNaN(n) ? undefined : { ['--k' as string]: n / max }}>
                {c}{!Number.isNaN(n) && n > 0 ? (diag ? ' ✓' : ' ✗') : ''}
              </td>);
          })}</tr>))}</tbody>
      </table>
      <p className="muted small">Rows are the expected disposition, columns what the rules produced. ✓ on the diagonal, ✗ off it is a miss.</p>
    </>
  );
}

function CatchRates({ detail }: { detail: Record<string, FaultDetail> }) {
  return (
    <table className="grid">
      <thead><tr><th>Mutation</th><th>Expected check</th><th>Fitted</th><th>Caught</th><th>Catch rate</th></tr></thead>
      <tbody>{Object.entries(detail).map(([id, d]) => (
        <tr key={id}>
          <td><b>{id}</b></td><td>{d.expected_check}</td><td>{d.fitted}</td><td>{d.caught}</td>
          <td>
            {d.catch_rate === null ? 'n/a' : (
              <span className="bar"><span className="bar-fill" style={{ width: `${d.catch_rate * 100}%` }} />
                <span className="bar-txt">{Math.round(d.catch_rate * 100)}%</span></span>)}
          </td>
        </tr>))}</tbody>
    </table>
  );
}

function Sweep({ s }: { s: SweepResult }) {
  const W = 760, H = 320, L = 56, B = 44, T = 16, R = 20;
  const xs = s.points.map((p) => p.threshold);
  const ymax = Math.max(1, ...s.points.flatMap((p) => [p.guess_attacks_detected, p.false_alerts, p.guess_attacks_total]));
  const x = (t: number) => L + ((t - Math.min(...xs)) / Math.max(1, Math.max(...xs) - Math.min(...xs))) * (W - L - R);
  const y = (v: number) => H - B - (v / ymax) * (H - B - T);
  const line = (f: (p: SweepResult['points'][number]) => number) =>
    s.points.map((p, i) => `${i ? 'L' : 'M'}${x(p.threshold)},${y(f(p))}`).join(' ');
  return (
    <>
      <svg viewBox={`0 0 ${W} ${H}`} className="chart" role="img"
           aria-label="R-GUESS threshold sweep: attacks detected against false alerts per threshold">
        {[0, 0.25, 0.5, 0.75, 1].map((f) => (
          <g key={f}><line x1={L} x2={W - R} y1={y(f * ymax)} y2={y(f * ymax)} className="gridline" />
            <text x={L - 8} y={y(f * ymax) + 5} textAnchor="end" className="axis">{Math.round(f * ymax)}</text></g>))}
        {xs.map((t) => <text key={t} x={x(t)} y={H - B + 22} textAnchor="middle" className="axis">{t}</text>)}
        <line x1={x(s.default_threshold)} x2={x(s.default_threshold)} y1={T} y2={H - B} className="default-line" />
        <text x={x(s.default_threshold) + 6} y={T + 12} className="axis">◀ default {s.default_threshold}</text>
        <path d={line((p) => p.guess_attacks_detected)} className="series-a" />
        <path d={line((p) => p.false_alerts)} className="series-b" />
        {s.points.map((p) => (<g key={p.threshold}>
          <circle cx={x(p.threshold)} cy={y(p.guess_attacks_detected)} r="6" className="dot-a"><title>{`threshold ${p.threshold}: ${p.guess_attacks_detected} attacks detected`}</title></circle>
          <rect x={x(p.threshold) - 6} y={y(p.false_alerts) - 6} width="12" height="12" className="dot-b"><title>{`threshold ${p.threshold}: ${p.false_alerts} false alerts`}</title></rect></g>))}
        <text x={(W + L) / 2} y={H - 6} textAnchor="middle" className="axis">R-GUESS threshold (failures)</text>
      </svg>
      <div className="legend"><span className="lg-a">● R-GUESS attacks detected</span> <span className="lg-b">■ False alerts</span></div>
      <table className="grid">
        <thead><tr><th>Threshold</th><th>Attacks detected</th><th>False alerts</th><th>R-GUESS attacks</th></tr></thead>
        <tbody>{s.points.map((p) => (
          <tr key={p.threshold} className={p.threshold === s.default_threshold ? 'lit' : ''}>
            <td>{p.threshold}{p.threshold === s.default_threshold ? ' ◀ default' : ''}</td>
            <td>{p.attacks_detected}/{p.attacks_total}</td><td>{p.false_alerts}/{p.benign_total}</td>
            <td>{p.guess_attacks_detected}/{p.guess_attacks_total}</td></tr>))}</tbody>
      </table>
      <p><Plain text={s.reading} block /></p>
      <p className="muted small"><Plain text={s.caveat} /></p>
    </>
  );
}

export function EvaluationPage() {
  const [data, setData] = useState<{ result: EvaluationResult | null; confusion: string[][] } | null>(null);
  const [sweep, setSweep] = useState<SweepResult | null | undefined>(undefined);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    api.evaluation().then(setData).catch((e: Error) => setError(e.message));
    api.sweep().then((r) => setSweep(r.result)).catch(() => setSweep(null));
  }, []);
  if (error) return <div className="error" role="alert"><Plain text={error} /></div>;
  if (!data) return <p className="muted">Loading…</p>;
  const r = data.result;
  if (!r) {
    return <Empty icon="📊" title="No measurement saved yet">Run <code>python -m soc_copilot.eval.run_suite</code> to write one to <code>results/</code>.</Empty>;
  }
  const catchRow = r.metrics.find((m) => m.name === 'Critic catch rate');
  const missed = r.metrics.filter((m) => m.verdict === 'MISSED').map((m) => m.name);
  const withMisses = r.metrics.filter((m) => m.misses.length > 0);
  return (
    <div className="page">
      <h2>Evaluation</h2>
      <SyntheticBanner />
      <p className="muted">Measurements on synthetic data: internal validity, not real-world detection performance. No analyst time saving is claimed.</p>
      <p className="small">measured {r.measured_on} · {r.mode} mode · config {r.config_hash} · kb {r.kb_hash}</p>
      <div className="stats">
        {Object.entries(r.datasets).map(([name, d]) => (
          <div className="stat" key={name}><div className="stat-n small-n">{d.split(',')[0]}</div><div>{name}</div></div>))}
      </div>
      <Card title="Metrics and acceptance criteria">
        <table className="grid">
          <thead><tr><th>Metric</th><th>Target</th><th>Measured</th><th>Verdict</th></tr></thead>
          <tbody>{r.metrics.map((m) => (
            <tr key={m.name} className={m.verdict === 'MISSED' ? 'row-bad' : ''}>
              <td title={m.definition}>{m.name}</td><td>{m.target}</td><td>{m.value}</td><td><b>{VERDICT[m.verdict] ?? m.verdict}</b></td></tr>))}</tbody>
        </table>
        {missed.length > 0
          ? <div className="error" role="alert">✗ Below target: {missed.join(', ')}</div>
          : <div className="notice">✓ Every metric with a target met it on this run.</div>}
      </Card>
      <div className="two">
        <Card title="Confusion matrix" note="per-account dispositions"><Confusion rows={data.confusion} /></Card>
        <Card title="Held-out set by template">
          <table className="grid">
            <thead><tr><th>Template</th><th>Cases</th><th>N-1 variants</th><th>Alert correct</th></tr></thead>
            <tbody>{Object.entries(r.heldout_by_template).map(([name, row]) => (
              <tr key={name}><td>{name}</td><td>{row.cases}</td><td>{row.below_threshold}</td><td>{row.alert_correct}/{row.cases}</td></tr>))}</tbody>
          </table>
        </Card>
      </div>
      {catchRow && typeof catchRow.detail === 'object' && (
        <Card title="Critic catch rate" note="one row per injected fault">
          <CatchRates detail={catchRow.detail} />
          <p className="muted small">A mutation is applied only to a report it fits, so the fitted count sits beside the rate: a fault that fitted nothing cannot show a perfect score.</p>
        </Card>
      )}
      <Card title="R-GUESS threshold sweep" note="is the default of five reasonable?">
        {sweep === undefined ? <p className="muted">Loading…</p>
          : sweep === null ? <Empty icon="📈" title="No sweep saved yet">Run <code>python -m soc_copilot.eval.sweep</code>.</Empty>
          : <Sweep s={sweep} />}
      </Card>
      <Card title={`Every miss (${withMisses.reduce((n, m) => n + m.misses.length, 0)})`}>
        {withMisses.length === 0
          ? <p className="muted">No metric recorded a miss on this run. The documented miss of the design (S9, low and slow) is not a held-out template, so it cannot appear here.</p>
          : withMisses.map((m) => (
            <details key={m.name}><summary>{m.name} ({m.misses.length})</summary>
              <pre className="raw"><Plain text={m.misses.join('\n')} /></pre></details>))}
      </Card>
    </div>
  );
}
