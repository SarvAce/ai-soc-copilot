import { META } from '../pipeline';
import type { NodeEvent, Stage1 } from '../types';

interface WorkflowTimelineProps {
  steps: NodeEvent[];
  revealed: number;
  selectedIndex: number;
  onSelectStep: (index: number) => void;
  stage1: Stage1 | null;
  status: string;
}

export function WorkflowTimeline({
  steps, revealed, selectedIndex, onSelectStep, stage1, status,
}: WorkflowTimelineProps) {
  const hasCase = Boolean(stage1?.cases.length);

  return (
    <div className="timeline-container">
      <div className="timeline-header">
        <div className="timeline-title">
          <span className="timeline-glyph" aria-hidden="true">⏱</span>
          <b>Execution Timeline</b>
          <span className="muted small">· Chronological step-by-step audit trace ({revealed} steps revealed)</span>
        </div>
        <div className="timeline-legend">
          <span className="legend-item"><span className="legend-dot dot-done" /> Done</span>
          <span className="legend-item"><span className="legend-dot dot-active" /> Active</span>
          <span className="legend-item"><span className="legend-dot dot-loop" /> Loop / Re-plan</span>
          <span className="legend-item"><span className="legend-dot dot-wait" /> HITL Pause</span>
        </div>
      </div>

      <div className="timeline-track" role="tablist" aria-label="Execution steps timeline">
        {/* Step 0: Detector (Stage 1) */}
        <button
          role="tab"
          aria-selected={selectedIndex === 0}
          className={`timeline-step ${selectedIndex === 0 ? 'selected' : ''} ${hasCase ? 'done' : 'idle'}`}
          onClick={() => onSelectStep(0)}
        >
          <div className="step-seq">0</div>
          <div className="step-content">
            <div className="step-name">Detector</div>
            <div className="step-sub">
              {stage1?.cases[0]?.rule ?? 'Stage 1'}
            </div>
          </div>
          <span className="step-status-icon" aria-hidden="true">{hasCase ? '✓' : '○'}</span>
        </button>

        {/* Steps 1..N */}
        {steps.map((step, i) => {
          const stepIndex = i + 1;
          const isRevealed = stepIndex <= revealed;
          const isSelected = selectedIndex === stepIndex;
          const isCurrent = stepIndex === revealed && status === 'running';
          const isLoop = ['re-plan', 'redraft', 'template'].includes(step.decision);
          const isPaused = step.node === 'analyst_review' && status === 'paused' && stepIndex === revealed;

          // Compute pass number for this node up to this step
          const passCount = steps.slice(0, stepIndex).filter((s) => s.node === step.node).length;

          let stateCls = 'pending';
          if (isCurrent) stateCls = 'current';
          else if (isPaused) stateCls = 'waiting';
          else if (isLoop) stateCls = 'loop';
          else if (isRevealed) stateCls = 'done';

          const meta = META[step.node] ?? {
            n: 0, title: step.node, role: '', input: '', output: '', source: 'rule' as const, sourceNote: '',
          };

          return (
            <button
              key={step.seq}
              role="tab"
              aria-selected={isSelected}
              disabled={!isRevealed}
              className={`timeline-step ${stateCls} ${isSelected ? 'selected' : ''}`}
              onClick={() => onSelectStep(stepIndex)}
            >
              <div className="step-seq">{step.seq}</div>
              <div className="step-content">
                <div className="step-name">
                  {meta.title}
                  {passCount > 1 && <span className="pass-pill">Pass {passCount}</span>}
                </div>
                <div className="step-sub">
                  <b>{step.decision}</b>
                </div>
              </div>
              <span className="step-status-icon" aria-hidden="true">
                {isCurrent && '◉'}
                {isPaused && '⏸'}
                {isLoop && '↺'}
                {!isCurrent && !isPaused && !isLoop && isRevealed && '✓'}
                {!isRevealed && '○'}
              </span>
            </button>
          );
        })}
      </div>
    </div>
  );
}
