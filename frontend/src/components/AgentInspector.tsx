import { useState } from 'react';
import { META } from '../pipeline';
import { useStore } from '../store';
import type { CaseDetail, Fact, NodeEvent, NodeName, QueryRecord, Stage1 } from '../types';
import { ChecksGrid, ClaimList, FactTable, QueryTable } from './provenance';
import { AuditBlock, PolarityBar, SourceFor } from './steps';
import {
  DispositionBadge, Plain, PriorityBadge, Src, paramText,
} from './ui';

interface AgentInspectorProps {
  node: NodeName | null;
  pass: number;
  onChangePass: (pass: number) => void;
  caseDetail: CaseDetail | null;
  stage1: Stage1 | null;
  steps: NodeEvent[];
}

export function AgentInspector({
  node, pass, onChangePass, caseDetail, stage1, steps,
}: AgentInspectorProps) {
  const [tab, setTab] = useState<'outputs' | 'inputs' | 'state' | 'audit'>('outputs');
  const { factById } = useStore();

  if (!node) {
    return (
      <div className="inspector-panel empty-inspector">
        <div className="empty-icon" aria-hidden="true">👆</div>
        <h3>Select an Agent</h3>
        <p className="muted">Click any agent node in the workflow graph or step in the timeline to inspect its inputs, outputs, and multi-pass execution history.</p>
      </div>
    );
  }

  const meta = META[node] ?? {
    n: 0, title: node, role: '', input: '', output: '', source: 'rule' as const, sourceNote: '',
  };
  const allExecs = steps.filter((s) => s.node === node);
  const currentExec = allExecs[pass - 1] ?? allExecs[allExecs.length - 1];

  // For Detector (Stage 1)
  if (node === 'detector') {
    const kase = caseDetail?.case ?? stage1?.cases[0];
    const quaranCount = stage1?.quarantined_count ?? 0;
    const acceptedCount = stage1?.events_accepted ?? 0;

    return (
      <div className="inspector-panel">
        <header className="inspector-head">
          <div className="inspector-badge">
            <span className="stepcard-n" aria-hidden="true">0</span>
            <div>
              <h3>Detector Agent</h3>
              <div className="muted small">{meta.role}</div>
            </div>
          </div>
          <div className="inspector-actions">
            <span className="pill pill-done">● STAGE 1 COMPLETED</span>
            <Src kind="rule" detail="sliding-window" />
          </div>
        </header>

        <div className="inspector-tabs" role="tablist">
          <button role="tab" aria-selected={tab === 'outputs'} className={tab === 'outputs' ? 'active' : ''} onClick={() => setTab('outputs')}>
            Outputs & Alerts
          </button>
          <button role="tab" aria-selected={tab === 'inputs'} className={tab === 'inputs' ? 'active' : ''} onClick={() => setTab('inputs')}>
            Input Stream
          </button>
          <button role="tab" aria-selected={tab === 'state'} className={tab === 'state' ? 'active' : ''} onClick={() => setTab('state')}>
            Detection Logic
          </button>
        </div>

        <div className="inspector-body">
          {tab === 'outputs' && (
            <div className="inspector-section">
              <h4>Case Created</h4>
              {kase ? (
                <div className="keyvals">
                  <div className="kv"><span className="k">Case ID</span><span className="v mono font-bold">{kase.case_id}</span></div>
                  <div className="kv"><span className="k">Triggered Rule</span><span className="v"><span className="chip chip-ok font-bold">{kase.rule}</span></span></div>
                  <div className="kv"><span className="k">Initial Hypothesis</span><span className="v"><span className="chip font-bold">{kase.hypothesis}</span></span></div>
                  <div className="kv"><span className="k">Targeted Accounts</span><span className="v">{kase.users.join(', ')}</span></div>
                  <div className="kv"><span className="k">Source IPs</span><span className="v mono">{kase.src_ips.join(', ')}</span></div>
                  <div className="kv"><span className="k">Time Window</span><span className="v small mono">{kase.window_start} → {kase.window_end}</span></div>
                  <div className="kv"><span className="k">Seed Event Count</span><span className="v">{kase.event_ids.length} failure events</span></div>
                </div>
              ) : (
                <p className="muted">No case was opened for this log. No rule threshold was crossed.</p>
              )}

              {quaranCount > 0 && (
                <>
                  <h4 style={{ marginTop: '1rem' }}>Quarantined Records ({quaranCount})</h4>
                  <p className="small muted">Malformed or missing essential fields (e.g. missing src_ip in S6b). Kept for data quality audits (E5).</p>
                  <div className="quarantine-mini-list">
                    {stage1?.quarantined.slice(0, 5).map((q, idx) => (
                      <div key={idx} className="quaran-item">
                        <span className="chip chip-bad">{q.reason}</span>
                        <code className="small">{q.raw.slice(0, 100)}…</code>
                      </div>
                    ))}
                  </div>
                </>
              )}
            </div>
          )}

          {tab === 'inputs' && (
            <div className="inspector-section">
              <h4>Input Stream Context</h4>
              <div className="keyvals">
                <div className="kv"><span className="k">Log Format</span><span className="v">Synthetic Single-Sign-On / VPN (JSONL)</span></div>
                <div className="kv"><span className="k">Accepted Events</span><span className="v font-bold">{acceptedCount} valid records</span></div>
                <div className="kv"><span className="k">Quarantined</span><span className="v">{quaranCount} records</span></div>
                <div className="kv"><span className="k">Coverage Span</span><span className="v small mono">{stage1?.coverage ? `${stage1.coverage.start} → ${stage1.coverage.end}` : 'N/A'}</span></div>
                <div className="kv"><span className="k">Historical Baseline</span><span className="v">14 days prior to analysis day</span></div>
              </div>
            </div>
          )}

          {tab === 'state' && (
            <div className="inspector-section">
              <h4>Sliding-Window Rule Table</h4>
              <table className="grid">
                <thead><tr><th>Rule</th><th>Threshold Condition</th><th>Initial Hypothesis</th></tr></thead>
                <tbody>
                  <tr><td><b>R-GUESS</b></td><td>≥5 failures / 10 min for 1 user from 1 IP</td><td><code>GUESS</code></td></tr>
                  <tr><td><b>R-SPRAY</b></td><td>≥6 users / 30 min from 1 IP, median ≤3 attempts</td><td><code>SPRAY</code></td></tr>
                  <tr><td><b>R-SAF</b></td><td>Sign-in success after ≥5 failures / 30 min</td><td><code>ATO</code></td></tr>
                </tbody>
              </table>
              <p className="small muted" style={{ marginTop: '0.6rem' }}>
                Bursts within 60 minutes are merged unless originating from a shared corporate VPN / NAT egress IP.
              </p>
            </div>
          )}
        </div>
      </div>
    );
  }

  // For Stage 2 Nodes (Planner, Investigator, Evidence Gate, Reporter, Report Gate, Analyst Review, Finalize)
  const queries: QueryRecord[] = caseDetail?.queries ?? currentExec?.produced.queries ?? [];
  const allFacts: Fact[] = [...factById.values()];
  const produced = currentExec?.produced;
  const received = currentExec?.received;

  return (
    <div className="inspector-panel">
      <header className="inspector-head">
        <div className="inspector-badge">
          <span className="stepcard-n" aria-hidden="true">{meta.n}</span>
          <div>
            <h3>{meta.title}</h3>
            <div className="muted small">{meta.role}</div>
          </div>
        </div>
        <div className="inspector-actions">
          <SourceFor node={node} step={currentExec} />
          {currentExec ? (
            <span className="pill pill-done">STEP {currentExec.seq}</span>
          ) : (
            <span className="pill pill-idle">NOT REACHED</span>
          )}
        </div>
      </header>

      {/* Multi-pass selector if this agent ran multiple times */}
      {allExecs.length > 1 && (
        <div className="pass-selector-bar" role="group" aria-label="Execution passes">
          <span className="pass-selector-label">Iteration / Pass:</span>
          {allExecs.map((exec, idx) => {
            const passNum = idx + 1;
            const isSelected = passNum === pass;
            return (
              <button
                key={exec.seq}
                className={`pass-btn ${isSelected ? 'active' : ''}`}
                onClick={() => onChangePass(passNum)}
              >
                Pass {passNum} <span className="small muted">(Step {exec.seq})</span>
              </button>
            );
          })}
        </div>
      )}

      {/* Main Tabs */}
      <div className="inspector-tabs" role="tablist">
        <button role="tab" aria-selected={tab === 'outputs'} className={tab === 'outputs' ? 'active' : ''} onClick={() => setTab('outputs')}>
          Outputs Generated
        </button>
        <button role="tab" aria-selected={tab === 'inputs'} className={tab === 'inputs' ? 'active' : ''} onClick={() => setTab('inputs')}>
          Inputs Received
        </button>
        <button role="tab" aria-selected={tab === 'state'} className={tab === 'state' ? 'active' : ''} onClick={() => setTab('state')}>
          State & Routing
        </button>
        <button role="tab" aria-selected={tab === 'audit'} className={tab === 'audit' ? 'active' : ''} onClick={() => setTab('audit')}>
          Audit & Checks
        </button>
      </div>

      <div className="inspector-body">
        {!currentExec ? (
          <div className="empty-state-notice">
            <p className="muted">This agent has not executed yet in the current run.</p>
          </div>
        ) : (
          <>
            {/* TAB 1: OUTPUTS GENERATED */}
            {tab === 'outputs' && (
              <div className="inspector-section">
                <div className="decision-banner">
                  <b>Decision:</b> <code>{currentExec.decision}</code>
                  {currentExec.reason && <div className="small muted"><Plain text={currentExec.reason} /></div>}
                </div>

                {/* Planner Output */}
                {node === 'planner' && (
                  <>
                    <h4>Planned Tool Calls ({produced?.plan?.length ?? 0})</h4>
                    {(produced?.plan ?? []).length === 0 ? (
                      <p className="muted small">No tool calls planned.</p>
                    ) : (
                      <table className="grid">
                        <thead><tr><th>Tool</th><th>Target / Parameters</th><th>Checklist Item</th></tr></thead>
                        <tbody>
                          {produced?.plan?.map((call, i) => (
                            <tr key={i}>
                              <td><span className="chip chip-tool">{call.tool}</span></td>
                              <td className="mono small">{paramText(call.params)}</td>
                              <td>{call.answers.map((a) => <span key={a} className="chip">{a}</span>)}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    )}
                  </>
                )}

                {/* Investigator Output */}
                {node === 'investigator' && (
                  <>
                    <h4>Executed Tool Queries ({produced?.queries?.length ?? 0})</h4>
                    <QueryTable queries={produced?.queries ?? []} facts={allFacts} />

                    <h4 style={{ marginTop: '1rem' }}>Facts Built ({produced?.facts?.length ?? 0})</h4>
                    <PolarityBar facts={produced?.facts ?? []} />
                    <FactTable facts={produced?.facts ?? []} queries={queries.length ? queries : (produced?.queries ?? [])} />

                    {(produced?.merged_facts?.length ?? 0) > 0 && (
                      <>
                        <h4 style={{ marginTop: '1rem' }}>Recomputed / Merged Facts ({produced?.merged_facts!.length})</h4>
                        <FactTable facts={produced?.merged_facts!} queries={queries} />
                      </>
                    )}

                    {(produced?.discoveries?.length ?? 0) > 0 && (
                      <div className="notice notice-warn" style={{ marginTop: '1rem' }}>
                        <b>⚡ Mid-Investigation Discoveries ({produced?.discoveries!.length})</b>
                        <ul>
                          {produced?.discoveries!.map((d, i) => (
                            <li key={i}>
                              <b>{d.kind}</b>: <Plain text={d.user || d.src_ip} /> (Pass {d.found_in_pass})
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </>
                )}

                {/* Evidence Gate Output */}
                {node === 'evidence_gate' && (
                  <>
                    <ChecksGrid report={produced?.evidence_check} title="Evidence Gate Verification (E1–E7)" />
                    {(produced?.evidence_check?.gaps?.length ?? 0) > 0 && (
                      <div className="notice notice-warn" style={{ marginTop: '1rem' }}>
                        <b>Open Gaps Identified:</b>
                        <ul>
                          {produced?.evidence_check!.gaps.map((g, i) => (
                            <li key={i}>
                              <span className="chip chip-bad">{g.gap_type}</span> <Plain text={g.detail} />
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </>
                )}

                {/* Reporter Output */}
                {node === 'reporter' && produced?.report && (
                  <>
                    <h4>Rule-Derived Verdict</h4>
                    <div className="chips">
                      <DispositionBadge value={produced.report.verdict.disposition} />
                      <PriorityBadge priority={produced.report.verdict.priority} />
                      <span className="chip">Impact: {produced.report.verdict.impact}</span>
                      <span className="chip">Rule Table 28 Row: {produced.report.verdict.row}</span>
                    </div>
                    <p className="small muted"><Plain text={produced.report.verdict.reason} /></p>

                    <h4 style={{ marginTop: '1rem' }}>Drafted Narrative ({produced.report.model_used})</h4>
                    <div className="narrative-box">
                      <Plain text={produced.report.summary} block />
                    </div>

                    <h4 style={{ marginTop: '1rem' }}>Claims ({produced.report.claims.length})</h4>
                    <ClaimList claims={produced.report.claims} source={currentExec.decision === 'draft' ? 'model' : 'template'} />
                  </>
                )}

                {/* Report Gate Output */}
                {node === 'report_gate' && (
                  <>
                    <ChecksGrid report={produced?.report_check} title="Report Gate Grounding Verification (R1–R10)" />
                    {(currentExec.received.errors?.length ?? 0) > 0 && (
                      <div className="notice notice-warn" style={{ marginTop: '1rem' }}>
                        <b>Errors Handed Back for Redraft:</b>
                        <ul>
                          {currentExec.received.errors!.map((err, i) => (
                            <li key={i}><Plain text={err} /></li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </>
                )}

                {/* Analyst Review Output */}
                {node === 'analyst_review' && (
                  <>
                    <h4>Human Analyst Decision</h4>
                    {produced?.decision ? (
                      <div className="keyvals">
                        <div className="kv"><span className="k">Action</span><span className="v font-bold">{produced.decision.action}</span></div>
                        <div className="kv"><span className="k">Analyst</span><span className="v">{produced.decision.analyst}</span></div>
                        {produced.decision.reason && (
                          <div className="kv"><span className="k">Justification</span><span className="v"><Plain text={produced.decision.reason} /></span></div>
                        )}
                      </div>
                    ) : (
                      <p className="notice notice-warn">⏸ LangGraph execution is currently paused at this node waiting for human input.</p>
                    )}
                  </>
                )}

                {/* Finalize Output */}
                {node === 'finalize' && (
                  <>
                    <h4>Final Case Resolution</h4>
                    <div className="chips">
                      <span className={`chip ${produced?.status === 'CLOSED' ? 'chip-ok' : 'chip-bad'} font-bold`}>
                        STATUS: {produced?.status}
                      </span>
                    </div>
                  </>
                )}
              </div>
            )}

            {/* TAB 2: INPUTS RECEIVED */}
            {tab === 'inputs' && (
              <div className="inspector-section">
                <h4>Data Received from Upstream</h4>
                {node === 'planner' && (
                  <div className="keyvals">
                    <div className="kv"><span className="k">Active Hypotheses</span><span className="v">{received?.hypotheses?.join(', ') || 'None'}</span></div>
                    <div className="kv"><span className="k">Open Gaps</span><span className="v">{(received?.gaps?.length ?? 0) === 0 ? 'None (Initial pass)' : received!.gaps!.map((g) => g.gap_type).join(', ')}</span></div>
                  </div>
                )}

                {node === 'investigator' && (
                  <div className="keyvals">
                    <div className="kv"><span className="k">Planned Checks</span><span className="v">{received?.plan?.length ?? 0} tool calls</span></div>
                  </div>
                )}

                {node === 'evidence_gate' && (
                  <div className="keyvals">
                    <div className="kv"><span className="k">Facts Received</span><span className="v">{received?.fact_count ?? 0}</span></div>
                    <div className="kv"><span className="k">Queries Executed</span><span className="v">{received?.query_count ?? 0}</span></div>
                  </div>
                )}

                {node === 'reporter' && (
                  <div className="keyvals">
                    <div className="kv"><span className="k">Validated Facts</span><span className="v">{received?.fact_count ?? 0}</span></div>
                    <div className="kv"><span className="k">Redraft Errors</span><span className="v">{received?.errors?.length ? received.errors.join('; ') : 'None (First draft)'}</span></div>
                  </div>
                )}

                {node === 'report_gate' && (
                  <div className="keyvals">
                    <div className="kv"><span className="k">Draft Claims</span><span className="v">{received?.draft?.claims?.length ?? 0} claims</span></div>
                    <div className="kv"><span className="k">Model Used</span><span className="v">{received?.draft?.model_used ?? 'N/A'}</span></div>
                  </div>
                )}

                {node === 'analyst_review' && (
                  <div className="keyvals">
                    <div className="kv"><span className="k">Pending Case File</span><span className="v">Released by Report Gate</span></div>
                  </div>
                )}

                {node === 'finalize' && (
                  <div className="keyvals">
                    <div className="kv"><span className="k">Input Decision</span><span className="v">{caseDetail?.decision?.action ?? 'Approve'}</span></div>
                  </div>
                )}
              </div>
            )}

            {/* TAB 3: STATE & ROUTING */}
            {tab === 'state' && (
              <div className="inspector-section">
                <h4>Transition & Routing</h4>
                <div className="keyvals">
                  <div className="kv"><span className="k">Route Written</span><span className="v mono font-bold">{currentExec.route || '— (unconditional edge)'}</span></div>
                  <div className="kv"><span className="k">Node Executions</span><span className="v mono">{currentExec.counters.node_executions} / 17</span></div>
                  <div className="kv"><span className="k">Evidence Retries</span><span className="v mono">{currentExec.counters.evidence_retries} / 2</span></div>
                  <div className="kv"><span className="k">Report Retries</span><span className="v mono">{currentExec.counters.report_retries} / 1</span></div>
                  <div className="kv"><span className="k">Template Fallback</span><span className="v">{currentExec.counters.used_template ? 'TRUE' : 'FALSE'}</span></div>
                </div>
              </div>
            )}

            {/* TAB 4: AUDIT & CHECKS */}
            {tab === 'audit' && (
              <div className="inspector-section">
                <h4>Cryptographic Audit Entry</h4>
                <AuditBlock step={currentExec} />
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
