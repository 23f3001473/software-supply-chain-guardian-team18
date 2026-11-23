import { useEffect, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import {
  Activity, Boxes, CircleAlert, ClipboardList, FileText, GitBranch, GitCompareArrows,
  LayoutGrid, List, Menu, Plus, ScanLine, Scale, Settings2, ShieldCheck, X,
} from 'lucide-react';
import { Blank, Changes, DependencyMap, Licence, Packages, Report, Repositories, Run, Sbom, Summary, Vulnerabilities } from './views';
import { Empty, Panel, Select, repoUrl, request, timestamp } from './ui';
import './styles.css';

const groups = [
  ['Inspection', [
    ['summary', 'Summary', LayoutGrid, Summary],
    ['packages', 'Packages', Boxes, Packages],
    ['dependency-map', 'Dependency map', GitBranch, DependencyMap],
    ['vulnerabilities', 'Vulnerabilities', CircleAlert, Vulnerabilities],
    ['changes', 'Changes', GitCompareArrows, Changes],
    ['licences', 'Licences', Scale, Licence],
    ['sbom', 'SBOM', ClipboardList, Sbom],
  ]],
  ['Workspace', [
    ['agent-run', 'Agent run', Activity, Run],
    ['repositories', 'All repositories', List, Repositories],
    ['report', 'Report', FileText, Report],
  ]],
];
const pages = groups.flatMap(([, items]) => items);
const readSection = () => pages.find(([key]) => '#' + key === window.location.hash)?.[0] ?? 'summary';
const scannerOptions = [['auto', 'OSV with npm audit fallback'], ['osv', 'OSV'], ['npm-audit', 'npm audit']];

function App() {
  const [section, setSection] = useState(readSection);
  const [repos, setRepos] = useState([]);
  const [selected, select] = useState('');
  const [snapshot, setSnapshot] = useState(null);
  const [revision, setRevision] = useState(0);
  const [listReady, setListReady] = useState(false);
  const [listError, setListError] = useState('');
  const [dataError, setDataError] = useState('');
  const [panel, setPanel] = useState('');
  const [menu, setMenu] = useState(false);
  const [job, setJob] = useState(null);
  const [submitting, setSubmitting] = useState(false);
  const [actionError, setActionError] = useState('');
  const [github, setGithub] = useState('');
  const [refresh, setRefresh] = useState(false);
  const [baseline, setBaseline] = useState('HEAD');
  const [scanner, setScanner] = useState('auto');
  const requestLock = useRef(false);
  const running = job?.status === 'running';
  const busy = running || submitting;
  const data = snapshot?.name === selected ? snapshot.data : null;
  const [, title, , View] = pages.find(([key]) => key === section);

  useEffect(() => {
    const update = () => setSection(readSection());
    window.addEventListener('hashchange', update);
    return () => window.removeEventListener('hashchange', update);
  }, []);

  function navigate(page) {
    window.location.hash = page;
    setSection(page);
    setMenu(false);
  }

  function selectRepo(name) {
    select(name);
    setDataError('');
    setBaseline('HEAD');
    setPanel('');
  }

  useEffect(() => {
    const controller = new AbortController();
    const opts = { signal: controller.signal };
    async function loadRepositories() {
      setListError('');
      try {
        const current = await request('/api/inspections', opts);
        if (current?.status === 'running') {
          setJob(current);
          return;
        }
        const entries = await request('/api/repositories', opts);
        setRepos(entries);
        select((name) => entries.some((repo) => repo.name === name) ? name :
          (entries.find((repo) => repo.name === 'juice-shop') ?? entries[0])?.name ?? '');
        setListReady(true);
      } catch (error) {
        if (!controller.signal.aborted) setListError(error.message);
      }
    }
    loadRepositories();
    return () => controller.abort();
  }, [revision]);

  useEffect(() => {
    if (!selected) return;
    const controller = new AbortController();
    request(repoUrl(selected), { signal: controller.signal })
      .then((value) => {
        setSnapshot({ name: selected, data: value });
        setDataError('');
      })
      .catch((error) => {
        if (!controller.signal.aborted) setDataError(error.message);
      });
    return () => controller.abort();
  }, [selected, revision]);

  const activeId = running ? job.id : null;
  useEffect(() => {
    if (!activeId) return;
    const controller = new AbortController();
    let timer;
    async function poll() {
      try {
        const current = await request('/api/inspections/' + activeId, { signal: controller.signal });
        setJob(current);
        setActionError('');
        if (current.status === 'running') {
          timer = window.setTimeout(poll, 900);
        } else {
          if (current.repository) selectRepo(current.repository);
          setRevision((value) => value + 1);
        }
      } catch (error) {
        if (controller.signal.aborted) return;
        if (error.status === 404) {
          setJob(null);
          setActionError('This inspection is no longer available. Check the saved report or start another inspection.');
          setRevision((value) => value + 1);
          return;
        }
        setActionError('Could not check inspection progress. ' + error.message);
        timer = window.setTimeout(poll, 2400);
      }
    }
    poll();
    return () => {
      controller.abort();
      window.clearTimeout(timer);
    };
  }, [activeId]);

  async function inspect(payload) {
    if (requestLock.current || busy) return;
    requestLock.current = true;
    setSubmitting(true);
    setActionError('');
    try {
      const { id } = await request('/api/inspections', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      setJob({ id, status: 'running', log: [] });
      setPanel('');
      setMenu(false);
      navigate('agent-run');
    } catch (error) {
      setActionError(error.message);
    } finally {
      requestLock.current = false;
      setSubmitting(false);
    }
  }

  const canInspect = Boolean(data?.commits.length);
  const report = data?.report;
  const isWorkspace = section === 'repositories';
  const retry = () => setRevision((value) => value + 1);

  return <div className="app-shell">
    <header className="mobile-header">
      <div className="brand"><ShieldCheck size={23} /><span>Guardian</span></div>
      <button aria-label={menu ? 'Close navigation' : 'Open navigation'} aria-expanded={menu}
        aria-controls="sidebar" onClick={() => setMenu(!menu)}>{menu ? <X size={18} /> : <Menu size={18} />}</button>
    </header>
    <aside id="sidebar" className={'sidebar' + (menu ? ' expanded' : '')}>
      <div className="desktop-brand">
        <div className="brand"><ShieldCheck size={26} strokeWidth={1.7} /><span>Guardian</span></div>
        <span className="muted">Supply chain inspection</span>
      </div>
      <div className="repo-control">
        <Select label="Repository" value={selected} onChange={selectRepo} disabled={busy || !repos.length}
          options={repos.length ? repos.map((repo) => [repo.name, repo.name]) : [['', 'No repositories']]} />
        <button className="add-repo" aria-expanded={panel === 'add'} aria-controls="inspection-form"
          disabled={busy} onClick={() => { setMenu(false); setPanel(panel === 'add' ? '' : 'add'); }}>
          <Plus size={17} /> Add repository
        </button>
      </div>
      <nav aria-label="Dashboard">
        {groups.map(([group, items]) => <div className="nav-group" key={group}>
          <p>{group}</p>
          {items.map(([key, label, Icon]) => <a key={key} href={'#' + key}
            aria-current={section === key ? 'page' : undefined}
            onClick={() => setMenu(false)}><Icon size={17} strokeWidth={1.75} />{label}</a>)}
        </div>)}
      </nav>
    </aside>
    <main id="main">
      <header className="page-head">
        <div>
          <h1>{section === 'summary' && selected ? selected : title}</h1>
          {!isWorkspace && selected && <div className="context">
            {section !== 'summary' && <span>{selected}</span>}
            {report?.commit && <span><GitBranch size={15} /><code title={report.commit}>{report.commit.slice(0, 9)}</code></span>}
            {report && <span>Inspected {timestamp(report.generated_at)}</span>}
            {report && data.commits.length === 0 && <span>Saved report</span>}
          </div>}
        </div>
        <div className="actions">
          {canInspect && <>
            <button disabled={busy} aria-expanded={panel === 'settings'} aria-controls="inspection-form"
              onClick={() => { setActionError(''); setPanel(panel === 'settings' ? '' : 'settings'); }}><Settings2 size={16} />Settings</button>
            <button className="primary" disabled={busy}
              onClick={() => inspect({ repository: selected, baseline, scanner })}><ScanLine size={16} />Inspect again</button>
          </>}
          {!canInspect && selected && <button className="primary" disabled={busy}
            onClick={() => { setActionError(''); setPanel('add'); }}><Plus size={17} /> Scan a repository</button>}
        </div>
      </header>

      {panel === 'add' && <Panel title="Add a GitHub repository" className="section-gap">
        <form id="inspection-form" onSubmit={(event) => {
          event.preventDefault();
          inspect({ github_url: github.trim(), refresh });
        }}>
          <label className="field"><span>Public GitHub repository link</span>
            <input required maxLength={2048} autoFocus value={github} onChange={(event) => setGithub(event.target.value)}
              placeholder="https://github.com/owner/repository" />
          </label>
          <label className="check"><input type="checkbox" checked={refresh}
            onChange={(event) => setRefresh(event.target.checked)} /> Replace the existing local clone with a fresh copy</label>
          <p className="muted">The repository must have a package.json at its root.</p>
          <button className="primary" disabled={busy || !github.trim()} type="submit">Fetch and inspect</button>
        </form>
      </Panel>}
      {panel === 'settings' && data && <Panel title="Inspection settings" className="section-gap">
        <div id="inspection-form" className="filters">
          <Select label="Compare changes against" value={baseline} onChange={setBaseline}
            options={data.commits.map(({ ref, label }) => [ref, label])} />
          <Select label="Advisory lookup" value={scanner} onChange={setScanner} options={scannerOptions} />
        </div>
        <p className="muted">Every inspection also runs offline dependency rules.</p>
      </Panel>}

      {actionError && <p className="notice" role="alert">{actionError}</p>}
      {listError && <p className="notice" role="alert">{listError} <button onClick={retry}>Retry</button></p>}
      {dataError && <p className="notice" role="alert">{dataError} <button onClick={retry}>Retry</button></p>}
      {report?.errors?.length > 0 && <p className="notice" role="alert">Agent errors in this inspection. <a href="#agent-run">View agent run</a>.</p>}
      {job && section !== 'agent-run' && (running || job.error) && <p className="notice" role="status">
        {running ? 'Inspection running.' : job.error} <a href="#agent-run">View progress</a>.
      </p>}

      {isWorkspace || section === 'agent-run' || report ? <View key={selected + section + revision}
        name={selected} data={data} job={job} repos={repos} busy={busy}
        selectRepo={(name) => { selectRepo(name); navigate('summary'); }} /> :
        listReady && (!selected || data) ? <Blank local={canInspect} name={selected} onAdd={() => setPanel('add')}
          busy={busy} onInspect={() => inspect({ repository: selected, baseline, scanner })} /> :
          !listError && !dataError && <Empty>Loading inspection data…</Empty>}
    </main>
  </div>;
}

createRoot(document.getElementById('root')).render(<App />);

