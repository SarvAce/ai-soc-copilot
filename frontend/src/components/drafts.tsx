import type { NodeEvent, Report } from '../types';
import { ClaimList } from './provenance';
import { Card, DispositionBadge, Empty, Plain, PriorityBadge, Src } from './ui';

function Draft({ report, tone, heading, step }: {
  report: Report; tone: 'bad' | 'ok'; heading: string; step: NodeEvent;
}) {
  const kind = step.decision === 'draft' ? 'model' : 'template';
  return (
    <div className={`draft draft-${tone}`}>
      <h4>{heading}</h4>
      <div className="chips">
        <Src kind={kind} detail={report.model_used} />
        <DispositionBadge value={report.verdict.disposition} />
        <PriorityBadge priority={report.verdict.priority} />
      </div>
      <p className="muted small">Verdict is set by rule (row {report.verdict.row}), so it is identical across drafts. Only the words below changed.</p>
      <Plain text={report.summary || '— no summary —'} block />
      <ClaimList claims={report.claims} source={kind} />
    </div>
  );
}

/** Rejected drafts are first-class: the draft, the checks that rejected it
 *  with their exact reasons, and the redraft beside it. */
export function DraftHistory({ steps }: { steps: NodeEvent[] }) {
  const rejections = steps
    .map((s, i) => ({ s, i }))
    .filter(({ s }) => s.node === 'report_gate' && s.produced.report_check
      && s.produced.report_check.checks.some((c) => !c.passed));
  if (rejections.length === 0) {
    return (
      <Card title="Draft history">
        <Empty icon="✓" title="No draft was rejected">
          The first draft passed all ten report checks, so there is no redraft to compare.
        </Empty>
      </Card>
    );
  }
  return (
    <Card title="Draft history" note="rejected draft · why · redraft">
      {rejections.map(({ s, i }, k) => {
        const failed = s.produced.report_check!.checks.filter((c) => !c.passed);
        const draft = s.received.draft;
        const next = steps.slice(i + 1).find((x) => x.node === 'reporter');
        return (
          <div key={s.seq} className="draftpair">
            <div className="draftpair-reasons">
              <b>Rejection {k + 1} · Report Gate step {s.seq} · decision {s.decision}</b>
              <ul>
                {failed.map((c) => (
                  <li key={c.check_id} className="reason"><b>✗ {c.check_id}</b> <Plain text={c.reason} /></li>
                ))}
              </ul>
            </div>
            <div className="draftpair-cols">
              {draft
                ? <Draft report={draft} tone="bad" heading="✗ Rejected draft" step={steps[i - 1] ?? s} />
                : <p className="muted">Draft not available.</p>}
              {next?.produced.report
                ? <Draft report={next.produced.report} tone="ok" heading={next.decision === 'draft' ? '↺ Redraft' : '▣ Template run'} step={next} />
                : <div className="draft"><h4>No redraft</h4><p className="muted">No redraft follows: the case is released flagged, with facts only.</p></div>}
            </div>
          </div>
        );
      })}
    </Card>
  );
}
