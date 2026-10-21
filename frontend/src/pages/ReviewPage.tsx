import { useState } from 'react';
import { Card, Empty, Plain } from '../components/ui';
import { AuditBlock } from '../components/steps';
import { useStore } from '../store';
import { CaseFile } from './CaseFile';

function DecisionPanel() {
  const { detail, decide, status } = useStore();
  const [reason, setReason] = useState('');
  const [analyst, setAnalyst] = useState('analyst');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  if (!detail) return null;

  if (detail.decision) {
    const finalStep = detail.steps[detail.steps.length - 1];
    return (
      <Card title="Analyst decision" className="decision">
        <div className="chips">
          <span className="chip chip-ok">{detail.decision.action} by {detail.decision.analyst}</span>
          <span className="chip">{detail.status}</span>
        </div>
        {detail.decision.reason && <p><Plain text={detail.decision.reason} /></p>}
        <p className="muted small">This case is closed. Its record and final audit entry are written:</p>
        {finalStep && <AuditBlock step={finalStep} />}
      </Card>
    );
  }
  if (!detail.paused) {
    return (
      <Card title="Analyst decision"><p className="muted">The case is not waiting for a decision yet.{status === 'running' ? ' It is still running.' : ''}</p></Card>
    );
  }

  const act = async (action: 'Approve' | 'Override' | 'Escalate') => {
    setError(null);
    if (action === 'Override' && !reason.trim()) { setError('An override needs a reason.'); return; }
    setBusy(true);
    try { await decide(action, reason, analyst); } catch (e) { setError((e as Error).message); }
    setBusy(false);
  };
  return (
    <Card title="Analyst decision" note="the graph is paused here" className="decision">
      <label>Reason <span className="muted">(required to override)</span>
        <input value={reason} onChange={(e) => setReason(e.target.value)} />
      </label>
      <label>Analyst <input value={analyst} onChange={(e) => setAnalyst(e.target.value)} /></label>
      <div className="decision-btns">
        <button className="primary" disabled={busy} onClick={() => act('Approve')}>✓ Approve</button>
        <button disabled={busy} onClick={() => act('Override')}>✎ Override</button>
        <button className="danger" disabled={busy} onClick={() => act('Escalate')}>▲ Escalate</button>
      </div>
      {error && <div className="error" role="alert"><Plain text={error} /></div>}
    </Card>
  );
}

export function ReviewPage() {
  const { detail } = useStore();
  if (!detail?.report) {
    return <Empty icon="⏸" title="Nothing to review yet">Run the case on the Investigation page. It pauses here for the analyst.</Empty>;
  }
  return (
    <div className="page">
      <h2>Analyst review · {detail.case.case_id}</h2>
      <DecisionPanel />
      <CaseFile />
    </div>
  );
}
