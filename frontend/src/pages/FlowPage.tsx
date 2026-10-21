import { useState, useMemo } from 'react';
import { FlowGraph } from '../components/FlowGraph';
import { AgentInspector } from '../components/AgentInspector';
import { WorkflowTimeline } from '../components/WorkflowTimeline';
import { DraftHistory } from '../components/drafts';
import { PayloadDrawer, ProvenancePanel } from '../components/provenance';
import { Card, Empty, Plain } from '../components/ui';
import { loopsTaken, type EdgeInfo } from '../pipeline';
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
    stage1, caseId, status, steps, revealed, error, start,
    speedMs, setSpeedMs, fault, setFault, faultWhen, setFaultWhen, scenarios, detail,
    isReplaying, playReplay, pauseReplay, stepForward, stepBackward, restartReplay, jumpToStep,
    selectedNode, selectedPass, selectNode, setSelectedPass,
  } = useStore();

  const [edge, setEdge] = useState<EdgeInfo | null>(null);

  // Compute the active timeline step index (0 for Detector, 1..N for steps)
  // Must be called unconditionally before any early returns to satisfy React Rules of Hooks
  const currentTimelineIndex = useMemo(() => {
    if (selectedNode === 'detector') return 0;
    if (revealed === 0) return 0;
    // Find step corresponding to selectedNode and selectedPass
    if (selectedNode) {
      const matchIdx = steps.slice(0, revealed).findIndex((s, i) => {
        const passOfThis = steps.slice(0, i + 1).filter((item) => item.node === selectedNode).length;
        return s.node === selectedNode && passOfThis === selectedPass;
      });
      if (matchIdx >= 0) return matchIdx + 1;
    }
    return revealed;
  }, [selectedNode, selectedPass, steps, revealed]);

  if (stage1 && stage1.cases.length === 0) {
    return (
      <Empty icon="∅" title="Nothing found, and that is the correct outcome">
        The Detector opened no case for this log, so there is no investigation to run. This is not an error:
        no rule threshold was crossed.
      </Empty>
    );
  }
  if (error && !caseId) {
    return (
      <div className="page flow-page">
        <div className="notice notice-bad" role="alert" style={{ margin: '2rem 0' }}>
          <h3>⚠️ Unable to connect to backend server</h3>
          <p>The frontend cannot connect to the AI-SOC Copilot FastAPI backend on <code>http://127.0.0.1:8000</code>.</p>
          <pre className="mono small" style={{ background: 'var(--panel2)', padding: '0.8rem', borderRadius: '6px' }}>{error}</pre>
          <p className="small muted">
            Make sure the backend server is running: <code>.venv/bin/python -m uvicorn soc_copilot.api.app:app --port 8000</code>
          </p>
        </div>
      </div>
    );
  }
  if (!caseId) {
    return (
      <div className="page flow-page">
        <p className="muted" style={{ padding: '2rem', textAlign: 'center' }}>⏳ Loading investigation scenario…</p>
      </div>
    );
  }

  const busy = status === 'running';

  const handleSelectTimelineStep = (stepIdx: number) => {
    jumpToStep(stepIdx);
    if (stepIdx === 0) {
      selectNode('detector', 1);
    } else {
      const step = steps[stepIdx - 1];
      if (step) {
        const passNum = steps.slice(0, stepIdx).filter((s) => s.node === step.node).length;
        selectNode(step.node, passNum || 1);
      }
    }
  };

  const handleOpenNode = (node: NodeName) => {
    if (node === 'detector') {
      selectNode('detector', 1);
      return;
    }
    // Find matching executions of this node in the revealed range
    const execs = steps.slice(0, revealed).filter((s) => s.node === node);
    if (execs.length > 0) {
      selectNode(node, execs.length);
    } else {
      selectNode(node, 1);
    }
  };

  return (
    <div className="page flow-page">
      {/* Top Toolbar */}
      <div className="toolbar flow-toolbar" role="toolbar" aria-label="Investigation execution controls">
        <button
          className="primary run-btn"
          onClick={start}
          disabled={busy}
          title="Run the case against the backend LangGraph engine"
        >
          {busy ? '⏳ Executing…' : `▶ ${detail?.started ? 'Run this case again' : 'Run this case'}`}
        </button>

        {/* Stepper & Replay Controls */}
        <div className="replay-controls" role="group" aria-label="Replay and step navigation">
          {isReplaying ? (
            <button className="ctrl-btn" onClick={pauseReplay} title="Pause automatic replay" aria-label="Pause replay">
              ⏸ Pause
            </button>
          ) : (
            <button
              className="ctrl-btn"
              onClick={playReplay}
              disabled={steps.length === 0 || busy}
              title="Auto-play execution trace step-by-step"
              aria-label="Play replay"
            >
              ▶ Play
            </button>
          )}

          <button
            className="ctrl-btn"
            onClick={stepBackward}
            disabled={revealed <= 0 || busy}
            title="Step backward to previous agent transition"
            aria-label="Step backward"
          >
            ⏮ Step Back
          </button>

          <button
            className="ctrl-btn"
            onClick={stepForward}
            disabled={revealed >= steps.length || busy}
            title="Step forward to next agent transition"
            aria-label="Step forward"
          >
            ⏭ Step Forward
          </button>

          <button
            className="ctrl-btn"
            onClick={restartReplay}
            disabled={steps.length === 0 || busy}
            title="Restart replay from the beginning"
            aria-label="Restart replay"
          >
            ↺ Restart
          </button>
        </div>

        {/* Settings: Pace & Fault Injection */}
        <label className="ctrl-label">
          Pace
          <input
            type="range"
            min={300}
            max={2500}
            step={100}
            value={speedMs}
            onChange={(e) => setSpeedMs(Number(e.target.value))}
            title={`Step transition pace: ${speedMs}ms`}
          />
          <span className="mono small">{speedMs}ms</span>
        </label>

        <label className="ctrl-label">
          Fault
          <select value={fault} onChange={(e) => setFault(e.target.value)}>
            <option value="off">off</option>
            {scenarios?.faults.map((f) => <option key={f}>{f}</option>)}
          </select>
        </label>

        <label className="ctrl-label">
          when
          <select
            value={faultWhen}
            onChange={(e) => setFaultWhen(e.target.value as 'first' | 'always')}
            disabled={fault === 'off'}
          >
            <option value="first">first draft only</option>
            <option value="always">every draft</option>
          </select>
        </label>

        {/* Status Line */}
        <div className="statusline" role="status">
          {status === 'running' && (
            <span className="live-status-pill status-running">● LIVE BACKEND EXECUTION</span>
          )}
          {status === 'paused' && !isReplaying && (
            <span className="live-status-pill status-paused">⏸ PAUSED AT ANALYST REVIEW (HITL)</span>
          )}
          {isReplaying && (
            <span className="live-status-pill status-replaying">▶ REPLAYING (Step {revealed}/{steps.length})</span>
          )}
          {!isReplaying && status !== 'running' && status !== 'paused' && steps.length > 0 && (
            <span className="live-status-pill status-inspecting">🔍 INSPECTING (Step {revealed}/{steps.length})</span>
          )}
          {status === 'closed' && (
            <span className="live-status-pill status-closed">■ CASE {detail?.status ?? 'CLOSED'}</span>
          )}
          {status === 'idle' && (
            <span className="live-status-pill status-idle">○ NOT RUN YET</span>
          )}
        </div>
      </div>

      {error && <div className="error" role="alert"><Plain text={error} /></div>}
      <LoopBanners />

      {steps.length === 0 && status !== 'running' && (
        <Card>
          <p className="muted">
            Press <b>Run this case</b> to watch the actual LangGraph agents execute.
            Stage 1 Detector opens the case; Stage 2 Planner, Investigator, Evidence Gate, Reporter, and Report Gate
            investigate the burst; LangGraph interrupts for Analyst review; and Finalize cryptographically seals the audit chain.
          </p>
        </Card>
      )}

      {/* Main Split Layout: Interactive Graph (Left/Center) + Agent Inspector (Right) */}
      <div className="flow-split-layout">
        <div className="flow-canvas-wrapper">
          <FlowGraph
            selectedNode={selectedNode}
            selectedPass={selectedPass}
            onNode={handleOpenNode}
            onEdge={setEdge}
          />
        </div>

        <div className="flow-inspector-wrapper">
          <AgentInspector
            node={selectedNode}
            pass={selectedPass}
            onChangePass={setSelectedPass}
            caseDetail={detail}
            stage1={stage1}
            steps={steps.slice(0, revealed)}
          />
        </div>
      </div>

      {/* Bottom Section: Chronological Execution Timeline */}
      <WorkflowTimeline
        steps={steps}
        revealed={revealed}
        selectedIndex={currentTimelineIndex}
        onSelectStep={handleSelectTimelineStep}
        stage1={stage1}
        status={status}
      />

      {/* Auxiliary Panels: Draft History & Provenance Inspector */}
      {steps.length > 0 && revealed >= steps.length && (
        <div className="auxiliary-panels">
          <DraftHistory steps={steps} />
          <ProvenancePanel />
        </div>
      )}

      {/* Edge Payload Drawer */}
      {edge && (
        <PayloadDrawer
          title={`${edge.source} → ${edge.target}`}
          subtitle={`${edge.payloadTitle} · walked ×${edge.count}`}
          data={edge.payload}
          onClose={() => setEdge(null)}
        />
      )}
    </div>
  );
}
