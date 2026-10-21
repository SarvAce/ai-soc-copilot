// Contracts derived from the backend's Pydantic models (see the brief, §3).
// The NodeEvent envelope carries a few adapter extras (route, model, received,
// entry) beside the fields of the brief; nothing here is computed client-side.

export type Disposition =
  | 'SUSPECTED_COMPROMISE' | 'LIKELY_BENIGN' | 'ATTACK_ATTEMPT_NO_ACCESS' | 'UNRESOLVED';
export type Priority = 'P1' | 'P2' | 'P3' | 'P4';
export type Polarity = 'MALICIOUS' | 'BENIGN' | 'NEUTRAL';
export type NodeName =
  | 'detector' | 'planner' | 'investigator' | 'evidence_gate' | 'reporter'
  | 'report_gate' | 'analyst_review' | 'finalize';

export interface Event {
  event_id: string;
  ts: string;
  event_type: string;
  user: string;
  outcome?: 'success' | 'failure' | null;
  failure_reason?: string;
  src_ip?: string;
  device_id?: string;
  country?: string;
  app?: string;
  user_agent?: string; // UNTRUSTED: display only
  raw?: string;
}

export interface Case {
  case_id: string;
  rule: 'R-GUESS' | 'R-SPRAY' | 'R-SAF';
  hypothesis: 'GUESS' | 'SPRAY' | 'ATO';
  users: string[];
  src_ips: string[];
  window_start: string;
  window_end: string;
  event_ids: string[];
  scenario_id?: string;
}

export interface ToolCall {
  tool: string;
  params: Record<string, unknown>;
  answers: string[];
}

export interface Coverage { start: string; end: string; complete: boolean; quarantined_count?: number }

export interface QueryRecord {
  query_id: string;
  label: string;
  tool: string;
  params: Record<string, unknown>;
  coverage?: Coverage | null;
  result_count: number;
}

export interface Fact {
  fact_id: string;
  label: string;
  kind: string;
  answers: string[];
  params: Record<string, unknown>;
  value: number | string | boolean;
  event_ids: string[];
  kb_ref?: string | null;
  query_id: string;
  coverage?: [string, string] | null;
  polarity: Polarity;
}

export interface Claim {
  text: string;
  fact_ids: string[];
  section: 'for' | 'against' | 'context';
}

export interface Gap { gap_type: string; detail: string; item?: string; user?: string }

export interface CheckResult {
  check_id: string;
  passed: boolean;
  reason: string;
  gap?: Gap | null;
  fact_ids: string[];
}

export interface ValidationReport {
  gate: 'EVIDENCE' | 'REPORT';
  checks: CheckResult[];
  gaps: Gap[];
  rejected_fact_ids: string[];
}

export interface AccountVerdict {
  user: string;
  disposition: Disposition;
  row: number;
  success_after: boolean;
  no_success_covered: boolean;
  malicious_indicator: boolean;
  benign_explanation: boolean;
}

export interface Verdict {
  disposition: Disposition;
  priority: Priority;
  impact: 'HIGH' | 'NORMAL';
  row: number;
  accounts: AccountVerdict[];
  reason: string;
}

export interface Recommendation {
  step_id: string;
  action: string;
  type: 'investigate' | 'contain' | 'communicate';
  requires_approval: boolean;
}

export interface TimelineItem { ts: string; text: string; event_id?: string }

export interface Report {
  case_id: string;
  mode: 'validated' | 'unresolved';
  summary: string;
  verdict: Verdict;
  triage_answers: Record<string, string>;
  claims: Claim[];
  timeline: TimelineItem[];
  unknowns: string[];
  recommendations: Recommendation[];
  attack_ids: string[];
  used_template: boolean;
  model_used: string;
}

export interface AuditEntry {
  seq: number;
  node: NodeName;
  decision: string;
  reason: string;
  fact_ids: string[];
  query_ids: string[];
  output_hash: string;
  prev_hash: string;
  entry_hash: string;
}

export interface Discovery {
  kind: 'SUCCESS' | 'NEW_IP' | 'NEW_DEVICE' | 'PERSISTENCE';
  user: string;
  src_ip: string;
  event_id: string;
  found_in_pass: number;
  checked: boolean;
}

export interface AnalystDecision { action: 'Approve' | 'Override' | 'Escalate'; reason: string; analyst: string }

export interface Counters {
  node_executions: number;
  evidence_retries: number;
  report_retries: number;
  used_template: boolean;
}

export interface Limits { node_executions: number; evidence_retries: number; report_retries: number }

export interface NodeEvent {
  seq: number;
  node: NodeName;
  decision: string;
  reason: string;
  route: string;
  model: string;
  produced: Partial<{
    plan: ToolCall[];
    queries: QueryRecord[];
    facts: Fact[];
    merged_facts: Fact[];
    timeline: TimelineItem[];
    discoveries: Discovery[];
    evidence_check: ValidationReport;
    report: Report;
    report_check: ValidationReport;
    decision: AnalystDecision;
    status: string;
  }>;
  received: Partial<{
    hypotheses: string[];
    gaps: Gap[];
    plan: ToolCall[];
    fact_count: number;
    query_count: number;
    errors: string[];
    draft: Report;
  }>;
  entry: AuditEntry | null;
  counters: Counters;
}

export interface CaseDetail {
  scenario_id: string;
  case: Case;
  limits: Limits;
  fault: string;
  synthetic: true;
  started: boolean;
  steps: NodeEvent[];
  status?: string;
  passes?: number;
  paused?: boolean;
  interrupt?: unknown;
  decision?: AnalystDecision | null;
  report?: Report | null;
  evidence_check?: ValidationReport | null;
  report_check?: ValidationReport | null;
  facts?: Fact[];
  queries?: QueryRecord[];
  timeline?: TimelineItem[];
  discoveries?: Discovery[];
  hypotheses?: string[];
  audit?: AuditEntry[];
  events?: Record<string, Event>;
  counters?: Counters;
}

export interface ScenarioList {
  scenarios: { scenario_id: string; title: string }[];
  faults: string[];
}

export interface Stage1 {
  scenario_id: string;
  title: string;
  events_accepted: number;
  quarantined_count: number;
  quarantined: { reason: string; raw: string; user?: string; src_ip?: string }[];
  coverage: Coverage | null;
  cases: (Case & { user_names: string[] })[];
}

export interface Metric {
  name: string; definition: string; target: string; value: string;
  detail: string; misses: string[]; verdict: string;
}

export interface FaultDetail { expected_check: string; fitted: number; caught: number; catch_rate: number | null }

export interface EvaluationResult {
  measured_on: string; mode: string; config_hash: string; kb_hash: string;
  datasets: Record<string, string>;
  metrics: (Metric & { detail: string | Record<string, FaultDetail> })[];
  heldout_by_template: Record<string, { cases: number; below_threshold: number; alert_correct: number }>;
}

export interface SweepPoint {
  threshold: number; attacks_detected: number; attacks_total: number;
  false_alerts: number; benign_total: number;
  guess_attacks_detected: number; guess_attacks_total: number;
}
export interface SweepResult { default_threshold: number; points: SweepPoint[]; reading: string; caveat: string }

export interface ArchitectureInfo {
  has_case: boolean;
  edges: { source: string; target: string; conditional: boolean }[];
  routes: Record<string, Record<string, string>>;
}
