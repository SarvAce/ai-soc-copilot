import { useState } from 'react';
import { FlowGraph } from '../components/FlowGraph';
import { DraftHistory } from '../components/drafts';
import { PayloadDrawer, ProvenancePanel } from '../components/provenance';
import { ExecutionDetail } from '../components/steps';
import { Card, Empty, Plain } from '../components/ui';
import { META, loopsTaken, type EdgeInfo } from '../pipeline';
import { useStore } from '../store';
import type { NodeName } from '../types';

function LoopBanners() {
  const { steps, revealed } = useStore();
  const notes = loopsTaken(steps.slice(0, revealed));
  if (notes.length === 0) return null;
  return (
    <div className="loops">
      {notes.map((n) => {
        const fresh = n.atIndex >= revealed - 2;
        return (
          <div key={n.atIndex} role="status" className={`loopbanner loop-${n.kind} ${fresh ? 'loop-fresh' : ''}`}>
            <span className="loop-glyph" aria-hidden="true">↺</span>
            <div>
              <div className="loop-title">{n.title}</div>
              <div>{n.detail}</div>
            </div>
          </div>
        );
      })}
    </div>
  );
}

export function FlowPage() {
  const {
    stage1, caseId, status, steps, revealed, error, start, skipAnimation,
    speedMs, setSpeedMs, fault, setFault, faultWhen, setFaultWhen, scenarios, detail,
  } = useStore();
  const [picked, setPicked] = useState<number | null>(null);
  const [edge, setEdge] = useState<EdgeInfo | null>(null);

  if (stage1 && stage1.cases.length === 0) {
    return (
      <Empty icon="∅" title="Nothing found, and that is the correct outcome">
        The Detector opened no case for this log, so there is no investigation to run. This is not an error:
        no rule threshold was crossed.
      </Empty>
    );
  }
  if (!caseId) return <p className="muted">Loading…</p>;

  const idx = picked !== null && picked < revealed ? picked : revealed - 1;
  const step = steps[idx];
  const busy = status === 'running' || revealed < steps.length;

  const openNode = (n: NodeName) => {
    const last = steps.slice(0, revealed).map((s, i) => ({ s, i })).filter(({ s }) => s.node === n).pop();
    if (last) setPicked(last.i);
  };

  return (
    <div className="page">
      <div className="toolbar">
        <button className="primary" onClick={() => { setPicked(null); start(); }} disabled={busy && status === 'running'}>
          ▶ {detail?.started ? 'Run this case again' : 'Run this case'}
        </button>
        <label>Fault injection
          <select value={fault} onChange={(e) => setFault(e.target.value)}>
            <option value="off">off</option>
            {scenarios?.faults.map((f) => <option key={f}>{f}</option>)}
          </select>
        </label>
        <label>when
          <select value={faultWhen} onChange={(e) => setFaultWhen(e.target.value as 'first' | 'always')} disabled={fault === 'off'}>
            <option value="first">first draft only</option><option value="always">every draft</option>
          </select>
        </label>
        <label>Pace {speedMs} ms
          <input type="range" min={200} max={2500} step={100} value={speedMs} onChange={(e) => setSpeedMs(Number(e.target.value))} />
        </label>
        <button onClick={skipAnimation} disabled={revealed >= steps.length}>Skip animation ⏭</button>
        <span className="statusline" role="status">
          {status === 'running' && 'Running…'}
          {status === 'paused' && revealed >= steps.length && '⏸ Paused at analyst review'}
          {status === 'closed' && `■ Case ${detail?.status ?? 'closed'}`}
          {status === 'idle' && 'Not run yet'}
        </span>
      </div>
      {error && <div className="error" role="alert"><Plain text={error} /></div>}
      <LoopBanners />

      {steps.length === 0 && status !== 'running' && (
        <Card><p className="muted">Press <b>Run this case</b> to watch the seven nodes execute. Facts come from tools, verdicts from rule tables, and the model only writes words.</p></Card>
      )}

      <FlowGraph onNode={openNode} onEdge={setEdge} />

      <div className="two">
        <Card title="Steps" note={`${revealed} of ${steps.length} shown`}>
          <ol className="steplist">
            {steps.slice(0, revealed).map((s, i) => (
              <li key={s.seq}>
                <button className={i === idx ? 'selected' : ''} onClick={() => setPicked(i)}>
                  <span className="stepcard-n" aria-hidden="true">{s.seq}</span>
                  <span><b>{META[s.node].title}</b> <span className="muted">· {s.decision}</span></span>
                </button>
              </li>
            ))}
          </ol>
        </Card>
        <ProvenancePanel />
      </div>

      {step && <Card><ExecutionDetail step={step} /></Card>}
      {steps.length > 0 && revealed >= steps.length && <DraftHistory steps={steps} />}

      {edge && <PayloadDrawer title={`${edge.source} → ${edge.target}`}
                              subtitle={`${edge.payloadTitle} · walked ×${edge.count}`}
                              data={edge.payload} onClose={() => setEdge(null)} />}
    </div>
  );
}
