import { Card, Empty, Plain, SyntheticBanner, fmtHM } from '../components/ui';
import { useStore } from '../store';

const WORDS: Record<string, string> = { GUESS: 'password guessing', SPRAY: 'password spraying', ATO: 'account takeover' };

export function QueuePage() {
  const { stage1, scenarioId, setCaseId, setPage, error } = useStore();
  if (error && !stage1) return <div className="error" role="alert"><Plain text={error} /></div>;
  if (!stage1) return <p className="muted">Loading scenario {scenarioId}…</p>;
  const cov = stage1.coverage;
  return (
    <div className="page">
      <h2>Alert queue · scenario {stage1.scenario_id} <span className="muted">{stage1.title}</span></h2>
      <div className="stats">
        <div className="stat"><div className="stat-n">{stage1.events_accepted.toLocaleString()}</div><div>events accepted</div></div>
        <div className="stat"><div className="stat-n">{stage1.quarantined_count}</div><div>quarantined</div></div>
        <div className="stat"><div className="stat-n">{stage1.cases.length}</div><div>cases opened</div></div>
        <div className="stat"><div className="stat-n small-n">{cov ? `${fmtHM(cov.start)}–${fmtHM(cov.end)}` : '—'}</div>
          <div>log coverage UTC{cov && !cov.complete ? ' · incomplete' : ''}</div></div>
      </div>
      <SyntheticBanner />
      {stage1.quarantined.length > 0 && (
        <Card title={`Quarantined records (${stage1.quarantined.length})`} note="the normaliser refused these; a case can be unresolved because of them">
          <ul className="raws">{stage1.quarantined.map((q, i) => (
            <li key={i}><b>{q.reason}</b> <pre className="raw"><Plain text={q.raw} /></pre></li>))}</ul>
        </Card>
      )}
      <h3>Cases found by the Detector</h3>
      {stage1.cases.length === 0 ? (
        <Empty icon="∅" title="No case was opened for this log">
          This is the expected outcome for this scenario: nothing crossed a detection threshold. It is not an error.
        </Empty>
      ) : stage1.cases.map((c) => (
        <Card key={c.case_id}>
          <div className="case-row">
            <div>
              <h3>{c.case_id} · {WORDS[c.hypothesis] ?? c.hypothesis}</h3>
              <div className="chips"><span className="chip chip-tool">{c.rule}</span><span className="chip">{c.hypothesis}</span></div>
              <p className="small">
                <b>{c.users.length}</b> account{c.users.length === 1 ? '' : 's'}: <Plain text={c.user_names.slice(0, 6).join(', ') + (c.users.length > 6 ? ' …' : '')} />
                <br />source <b>{c.src_ips.join(', ')}</b> · window {fmtHM(c.window_start)}–{fmtHM(c.window_end)} UTC · <b>{c.event_ids.length}</b> events
              </p>
            </div>
            <button className="primary" onClick={() => { setCaseId(c.case_id); setPage('flow'); }}>Investigate →</button>
          </div>
        </Card>
      ))}
    </div>
  );
}
