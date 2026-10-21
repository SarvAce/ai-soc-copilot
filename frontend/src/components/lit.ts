import type { Hover } from '../store';
import type { Fact } from '../types';

/** Which facts are lit by the current hover (claim -> facts, fact -> itself,
 *  event/query -> the facts that cite them). Pure highlighting, no derivation. */
export function factLit(hover: Hover, fact: Fact): boolean {
  if (!hover) return false;
  switch (hover.kind) {
    case 'fact': return hover.id === fact.fact_id;
    case 'claim': return hover.factIds.includes(fact.fact_id);
    case 'event': return fact.event_ids.includes(hover.id);
    case 'query': return fact.query_id === hover.id;
  }
}

export function eventLit(hover: Hover, eventId: string, facts: Iterable<Fact>): boolean {
  if (!hover) return false;
  if (hover.kind === 'event') return hover.id === eventId;
  for (const fact of facts) {
    if (hover.kind === 'fact' && fact.fact_id === hover.id && fact.event_ids.includes(eventId)) return true;
    if (hover.kind === 'claim' && hover.factIds.includes(fact.fact_id) && fact.event_ids.includes(eventId)) return true;
    if (hover.kind === 'query' && fact.query_id === hover.id && fact.event_ids.includes(eventId)) return true;
  }
  return false;
}

export function queryLit(hover: Hover, queryId: string, facts: Iterable<Fact>): boolean {
  if (!hover) return false;
  if (hover.kind === 'query') return hover.id === queryId;
  for (const fact of facts) {
    if (fact.query_id !== queryId) continue;
    if (hover.kind === 'fact' && fact.fact_id === hover.id) return true;
    if (hover.kind === 'claim' && hover.factIds.includes(fact.fact_id)) return true;
    if (hover.kind === 'event' && fact.event_ids.includes(hover.id)) return true;
  }
  return false;
}
