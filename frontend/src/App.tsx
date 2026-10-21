import { CounterBar, SyntheticBanner } from './components/ui';
import { ArchitecturePage } from './pages/ArchitecturePage';
import { CaseFile } from './pages/CaseFile';
import { EvaluationPage } from './pages/EvaluationPage';
import { FlowPage } from './pages/FlowPage';
import { QueuePage } from './pages/QueuePage';
import { ReviewPage } from './pages/ReviewPage';
import { StoreProvider, useStore, type Page } from './store';

const TABS: { id: Page; label: string }[] = [
  { id: 'queue', label: '1 Alert queue' },
  { id: 'flow', label: '2 Investigation' },
  { id: 'case', label: '3 Case file' },
  { id: 'review', label: '4 Analyst review' },
  { id: 'evaluation', label: '5 Evaluation' },
  { id: 'architecture', label: '6 Architecture' },
];

function Shell() {
  const { page, setPage, theme, toggleTheme, scenarios, scenarioId, setScenarioId, stage1, caseId, setCaseId, counters, limits } = useStore();
  return (
    <>
      <a className="skip" href="#main">Skip to content</a>
      <header className="top">
        <div className="brand"><span aria-hidden="true">🛡</span> AI-SOC Copilot <span className="badge-syn">SYNTHETIC DATA</span></div>
        <div className="pickers">
          <label>Scenario
            <select value={scenarioId} onChange={(e) => setScenarioId(e.target.value)}>
              {(scenarios?.scenarios ?? [{ scenario_id: scenarioId, title: '' }]).map((s) => (
                <option key={s.scenario_id} value={s.scenario_id}>{s.scenario_id} · {s.title}</option>))}
            </select>
          </label>
          <label>Case
            <select value={caseId ?? ''} onChange={(e) => setCaseId(e.target.value)} disabled={!stage1 || stage1.cases.length === 0}>
              {stage1 && stage1.cases.length === 0 && <option value="">no case opened</option>}
              {stage1?.cases.map((c) => <option key={c.case_id}>{c.case_id}</option>)}
            </select>
          </label>
          <button onClick={toggleTheme} aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}>{theme === 'dark' ? '☀ Light' : '☾ Dark'}</button>
        </div>
        <nav aria-label="Screens">
          {TABS.map((t) => (
            <button key={t.id} className={page === t.id ? 'tab tab-on' : 'tab'} aria-current={page === t.id ? 'page' : undefined}
                    onClick={() => setPage(t.id)}>{t.label}</button>))}
        </nav>
        <CounterBar counters={counters} limits={limits} />
      </header>
      <main id="main">
        {page === 'queue' && <QueuePage />}
        {page === 'flow' && <FlowPage />}
        {page === 'case' && <div className="page"><CaseFile /></div>}
        {page === 'review' && <ReviewPage />}
        {page === 'evaluation' && <EvaluationPage />}
        {page === 'architecture' && <ArchitecturePage />}
      </main>
      <footer><SyntheticBanner /></footer>
    </>
  );
}

export function App() {
  return <StoreProvider><Shell /></StoreProvider>;
}
