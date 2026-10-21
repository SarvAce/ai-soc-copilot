import { useEffect, useMemo, useRef, useState } from 'react';
import { api } from '../api';
import { STEP_COMPONENTS } from '../components/steps';
import { Card, Empty, SyntheticBanner } from '../components/ui';
import { EDGE_DEFS, META, NODES, edgeId, loopsTaken, nodeState } from '../pipeline';
import { useStore } from '../store';
import type { ArchitectureInfo, NodeName } from '../types';

function Connector({ from, loops }: { from: NodeName; loops?: ReactLoop[] }) {
  return (
    <div className="connector" aria-hidden={loops ? undefined : true}>
      <div className="connector-line" />
      <div className="connector-label">▼ {META[from].output}</div>
      {loops?.map((l) => (
        <div key={l.text} className={`loopribbon ${l.count ? 'loopribbon-on' : ''}`}>
          <span aria-hidden="true">↺</span> {l.text} <b>×{l.count}</b>
        </div>
      ))}
    </div>
  );
}
interface ReactLoop { text: string; count: number }

export function ArchitecturePage() {
  const { stage1, steps, scenarioId, caseId, status } = useStore();
  const [info, setInfo] = useState<ArchitectureInfo | null>(null);
  const [replay, setReplay] = useState(0);
  const [playing, setPlaying] = useState<number | null>(null);
  const timer = useRef<number | null>(null);

  useEffect(() => {
    if (!caseId) { setInfo(null); return; }
    api.architecture(scenarioId, caseId).then(setInfo).catch(() => setInfo(null));
  }, [scenarioId, caseId]);
  useEffect(() => () => { if (timer.current) window.clearInterval(timer.current); }, []);

  // "Play the run": light the steps in the order they executed.
  const play = () => {
    if (timer.current) window.clearInterval(timer.current);
    setReplay((n) => n + 1);
    let i = 0;
    setPlaying(0);
    timer.current = window.setInterval(() => {
      i += 1;
      if (i >= steps.length) { window.clearInterval(timer.current!); setPlaying(null); return; }
      setPlaying(i);
    }, 900);
  };

  const shown = useMemo(() => (playing === null ? steps : steps.slice(0, playing + 1)), [steps, playing]);
  const paused = status === 'paused';
  const loops = useMemo(() => loopsTaken(shown), [shown]);
  const count = (k: string) => loops.filter((l) => l.kind === k).length;

  if (stage1 && stage1.cases.length === 0) {
    return <Empty icon="∅" title="No case, so no thread to draw">Stage 1 ran and opened no case for this log. Stage 2 never starts.</Empty>;
  }

  const walked = new Map<string, number>();
  shown.forEach((s, i) => { const nxt = shown[i + 1]; if (nxt) walked.set(edgeId(s.node, nxt.node), (walked.get(edgeId(s.node, nxt.node)) ?? 0) + 1); });
  const compiled = new Set((info?.edges ?? []).map((e) => edgeId(e.source, e.target)));

  return (
    <div className="page">
      <h2>Architecture · scenario {scenarioId}</h2>
      <SyntheticBanner />
      <div className="toolbar">
        <button className="primary" onClick={play} disabled={steps.length === 0}>▶ Play the run through the pipeline</button>
        <button onClick={() => { setPlaying(null); setReplay((n) => n + 1); }}>↻ Replay entrance</button>
        {steps.length === 0 && <span className="muted">Run the case on the Investigation page to light up the nodes that ran.</span>}
      </div>

      <Card title="Stage 1" note="runs once per log">
        <div className="stage1">
          {[
            ['Normaliser', 'validates, quarantines', stage1 ? `${stage1.quarantined_count} quarantined` : ''],
            ['Event store', 'read-only', stage1 ? `${stage1.events_accepted.toLocaleString()} events` : ''],
            ['Detector', 'R-GUESS · R-SPRAY · R-SAF', stage1 ? `${stage1.cases.length} case(s)` : ''],
            ['Case queue', 'one thread per case', stage1 ? stage1.cases.map((c) => c.case_id).join(', ') : ''],
          ].map(([t, sub, stat], i) => (
            <div className="s1" key={t} style={{ animationDelay: `${i * 120}ms` }}>
              <b>{i + 1}. {t}</b><div className="muted small">{sub}</div><div className="chip">{stat}</div>
            </div>))}
        </div>
      </Card>

      <h3>Stage 2 · one LangGraph thread per case</h3>
      <p className="muted">Each step is its own component. The text under <b>IN</b> and <b>OUT</b> is the typed payload that crosses its edges.</p>
      <div className="pipeline" key={replay}>
        {NODES.map((node, i) => {
          const Step = STEP_COMPONENTS[node];
          const execs = shown.filter((s) => s.node === node);
          const state = nodeState(node, shown, playing === null, paused);
          const ringLoops: ReactLoop[] | undefined =
            node === 'evidence_gate' ? [{ text: 'RE-PLAN back to step 1 (Planner)', count: count('re-plan') }]
            : node === 'report_gate' ? [
              { text: 'REDRAFT back to step 4 (Reporter)', count: count('redraft') },
              { text: 'TEMPLATE back to step 4, runs once', count: count('template') }]
            : undefined;
          return (
            <div key={node} className="pipe-item">
              <Step execs={execs} state={state} index={i} />
              {i < NODES.length - 1 && <Connector from={node} loops={ringLoops} />}
            </div>
          );
        })}
        <div className="pipe-end">■ END · status becomes CLOSED or ESCALATED</div>
      </div>

      <Card title="Designed pipeline beside the compiled graph" note="read from the StateGraph itself">
        {!info ? <p className="muted">Compiled graph not loaded.</p> : (
          <table className="grid">
            <thead><tr><th>Edge</th><th>Designed</th><th>In compiled graph</th><th>Walked in this run</th></tr></thead>
            <tbody>
              {EDGE_DEFS.map((d) => {
                const id = edgeId(d.source, d.target);
                const n = walked.get(id) ?? (d.target === '__end__' && shown.at(-1)?.node === 'finalize' ? 1 : 0);
                return (
                  <tr key={id} className={n ? 'lit' : ''}>
                    <td>{d.source} → {d.target === '__end__' ? 'END' : d.target}{d.loop ? ' ↺' : ''}</td>
                    <td>✓ {d.idle}</td>
                    <td>{compiled.has(id) ? '✓ present' : '✗ MISSING'}</td>
                    <td>{n ? `● ×${n}` : '○ not walked'}</td>
                  </tr>);
              })}
            </tbody>
          </table>
        )}
        {info && Object.entries(info.routes).map(([gate, table]) => (
          <p key={gate} className="small"><b>{gate}</b> can write: {Object.entries(table).map(([route, to]) => (
            <span key={route} className="chip">{route} → {to}</span>))}</p>))}
      </Card>
    </div>
  );
}
