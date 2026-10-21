import { useState } from 'react';
import { DraftHistory } from '../components/drafts';
import {
  ChecksGrid, ClaimList, EventLine, FactTable, ProvenancePanel, QueryTable,
} from '../components/provenance';
import {
  Card, DispositionBadge, Empty, Plain, PriorityBadge, Src, SyntheticBanner, fmtTime,
} from '../components/ui';
import { useStore } from '../store';
import type { Claim } from '../types';

const SECTIONS: { key: Claim['section']; title: string }[] = [
  { key: 'for', title: '▲ Evidence for' },
  { key: 'against', title: '▼ Evidence against' },
  { key: 'context', title: '● Context' },
];

export function CaseFile() {
  const { detail, steps } = useStore();
  const [openEvent, setOpenEvent] = useState<string | null>(null);
  const report = detail?.report;
  if (!detail || !report) {
    return (
      <Empty icon="📄" title="No case file yet">
        Run the case on the <b>Investigation</b> page first. The case file is what the analyst receives at the end.
      </Empty>
    );
  }
  const v = report.verdict;
  const source = report.used_template ? 'template' : 'model';
  const events = detail.events ?? {};
  const failedReport = detail.report_check?.checks.some((c) => !c.passed);

  return (
    <div className="casefile">
      <div className="main">
        <SyntheticBanner />
        {report.mode === 'unresolved' && (
          <div className="notice">
            <b>? UNRESOLVED is a correct outcome.</b> There is not enough evidence to decide, and the report says so
            rather than guessing. See the unknowns below.
          </div>
        )}
        {failedReport && (
          <div className="notice notice-warn"><b>⚠ The Report Gate could not pass this draft.</b> It is shown flagged, with facts only.</div>
        )}

        <Card title={`Case ${report.case_id}`} note={`${detail.case.rule} · ${detail.hypotheses?.join(', ')}`}>
          <div className="verdict">
            <DispositionBadge value={v.disposition} />
            <PriorityBadge priority={v.priority} />
            <span className="chip">impact {v.impact}</span>
            <Src kind="rule" detail={`disposition table row ${v.row}`} />
          </div>
          <p><Plain text={v.reason} /></p>
          <table className="grid">
            <thead><tr><th>Account</th><th>Disposition</th><th>Row</th><th>Success after</th><th>No success covered</th><th>Malicious indicator</th><th>Benign explanation</th></tr></thead>
            <tbody>{v.accounts.map((a) => (
              <tr key={a.user}><td><Plain text={a.user} /></td><td><DispositionBadge value={a.disposition} /></td><td>row {a.row}</td>
                <td>{a.success_after ? '✓ yes' : '✗ no'}</td><td>{a.no_success_covered ? '✓ yes' : '✗ no'}</td>
                <td>{a.malicious_indicator ? '✓ yes' : '✗ no'}</td><td>{a.benign_explanation ? '✓ yes' : '✗ no'}</td></tr>))}</tbody>
          </table>
          <p className="muted small">The table row is the one the rules matched. Neither model nor browser can change it.</p>
        </Card>

        <Card title="Summary" right={<Src kind={source} detail={report.model_used} />}>
          <Plain text={report.summary} block />
          <p className="muted small">Plain text, never rendered as markdown or HTML (check R10).</p>
        </Card>

        <Card title="Triage questions" note="Q1–Q6" right={<Src kind="tool" detail="sentence library over facts" />}>
          <dl className="triage">
            {Object.entries(report.triage_answers).map(([q, a]) => (<div key={q}><dt>{q}</dt><dd><Plain text={a} /></dd></div>))}
          </dl>
        </Card>

        {SECTIONS.map(({ key, title }) => {
          const claims = report.claims.filter((c) => c.section === key);
          return claims.length === 0 ? null : (
            <Card key={key} title={title} right={<Src kind="rule" detail="section from polarity" />}>
              <ClaimList claims={claims} source={source} />
            </Card>
          );
        })}

        <Card title="Unknowns" note="what the report admits it does not know">
          {report.unknowns.length === 0 ? <p className="muted">None recorded.</p>
            : <ul>{report.unknowns.map((u, i) => <li key={i}>? <Plain text={u} /></li>)}</ul>}
        </Card>

        <Card title="Timeline" note="click an event to see its raw line" right={<Src kind="tool" />}>
          <ol className="timeline">
            {report.timeline.map((t, i) => (
              <li key={i}>
                <button onClick={() => setOpenEvent(openEvent === t.event_id ? null : (t.event_id ?? null))} disabled={!t.event_id}>
                  <span className="mono">{fmtTime(t.ts)}</span> <Plain text={t.text} /> <span className="muted">{t.event_id}</span>
                </button>
                {openEvent && openEvent === t.event_id && events[openEvent] && <EventLine event={events[openEvent]} />}
              </li>))}
          </ol>
        </Card>

        <Card title="Recommended next steps" right={<Src kind="rule" detail="playbook" />}>
          <ul className="recs">
            {report.recommendations.map((r) => (
              <li key={r.step_id}>
                <code>{r.step_id}</code> <Plain text={r.action} /> <span className="chip">{r.type}</span>
                {r.requires_approval
                  ? <span className="chip chip-bad">🔒 needs approval</span>
                  : <span className="chip chip-ok">no approval needed</span>}
              </li>))}
          </ul>
          <p className="muted small">Recommendations are offered, never executed.</p>
        </Card>

        <Card title="ATT&CK techniques" right={<Src kind="rule" detail="playbook mapping" />}>
          {report.attack_ids.length === 0 ? <p className="muted">None cited.</p>
            : <div className="chips">{report.attack_ids.map((a) => <span key={a} className="chip chip-tool">{a}</span>)}</div>}
        </Card>

        <Card title="Validation" note="every check individually">
          <ChecksGrid report={detail.evidence_check} title="Evidence Gate · E1–E7 (final pass)" />
          <ChecksGrid report={detail.report_check} title="Report Gate · R1–R10 (final draft)" />
        </Card>

        <DraftHistory steps={steps} />

        <Card title="Facts and queries" note={`${detail.facts?.length ?? 0} facts`}>
          <QueryTable queries={detail.queries ?? []} facts={detail.facts ?? []} />
          <FactTable facts={detail.facts ?? []} queries={detail.queries ?? []} />
        </Card>
      </div>
      <div className="side"><ProvenancePanel /></div>
    </div>
  );
}
