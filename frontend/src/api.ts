import type {
  ArchitectureInfo, CaseDetail, EvaluationResult, NodeEvent, ScenarioList,
  Stage1, SweepResult, AnalystDecision, Limits,
} from './types';

const BASE = '/api';

async function json<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(BASE + path, init);
  if (!res.ok) {
    let message = `${res.status} ${res.statusText}`;
    try {
      const body = (await res.json()) as { detail?: string };
      if (body.detail) message = body.detail;
    } catch { /* keep the status text */ }
    throw new Error(message);
  }
  return (await res.json()) as T;
}

export const api = {
  scenarios: () => json<ScenarioList>('/scenarios'),
  stage1: (scenario: string) => json<Stage1>(`/scenarios/${scenario}`),
  detail: (scenario: string, caseId: string) =>
    json<CaseDetail>(`/cases/${caseId}?scenario=${scenario}`),
  decide: (scenario: string, caseId: string, d: Partial<AnalystDecision>) =>
    json<CaseDetail>(`/cases/${caseId}/decision?scenario=${scenario}`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(d),
    }),
  architecture: (scenario: string, caseId: string) =>
    json<ArchitectureInfo>(`/architecture?scenario=${scenario}&case=${caseId}`),
  evaluation: () =>
    json<{ result: EvaluationResult | null; confusion: string[][] }>('/evaluation'),
  sweep: () => json<{ result: SweepResult | null }>('/sweep'),
};

export type StreamMessage =
  | { type: 'start'; limits: Limits }
  | { type: 'node'; event: NodeEvent }
  | { type: 'paused'; detail: CaseDetail }
  | { type: 'error'; message: string }
  | { type: 'done' };

/** POST + SSE: EventSource cannot POST, so the stream is parsed by hand. */
export async function runCase(
  scenario: string, caseId: string, fault: string, faultWhen: string,
  onMessage: (m: StreamMessage) => void, signal: AbortSignal,
): Promise<void> {
  const query = new URLSearchParams({ scenario, fault, fault_when: faultWhen });
  const res = await fetch(`${BASE}/cases/${caseId}/run?${query}`, { method: 'POST', signal });
  if (!res.ok || !res.body) throw new Error(`run failed: ${res.status} ${res.statusText}`);
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    let cut: number;
    while ((cut = buffer.indexOf('\n\n')) >= 0) {
      const block = buffer.slice(0, cut);
      buffer = buffer.slice(cut + 2);
      let name = 'message';
      let data = '';
      for (const line of block.split('\n')) {
        if (line.startsWith('event: ')) name = line.slice(7);
        else if (line.startsWith('data: ')) data += line.slice(6);
      }
      const payload = data ? JSON.parse(data) : {};
      if (name === 'start') onMessage({ type: 'start', limits: payload.limits });
      else if (name === 'node') onMessage({ type: 'node', event: payload });
      else if (name === 'paused') onMessage({ type: 'paused', detail: payload });
      else if (name === 'error') onMessage({ type: 'error', message: payload.message });
      else if (name === 'done') onMessage({ type: 'done' });
    }
  }
}
