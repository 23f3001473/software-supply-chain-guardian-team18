import { useMemo, useState } from 'react';
import Markdown from 'react-markdown';
import { Check, ChevronRight, CircleAlert, GitBranch, ScanLine } from 'lucide-react';
import {
  Bars, DownloadLink, Empty, Panel, Resource, Search, Select, Severity, Table,
  artifactUrl, bySeverity, capitalize, count, packageId, repoUrl, scopeOptions,
  severities, severityRank, tally, timestamp, useArtifact, useResource,
} from './ui';

const allScopes = (row, scope) => !scope || (row.scope === 'prod') === (scope === 'prod');
const findingsOf = (data) => data.vulnerabilities.findings ?? [];
const offlineRows = (data) => (data.offlineFindings ?? []).map((row) => ({
  ...row, id: row.rule, installed_version: row.version, title: row.message, offline: true,
}));
const sourceNames = { osv: 'OSV', 'npm-audit': 'npm audit', offline: 'Offline rules' };
function findingSource(row) {
  if (row.offline) return 'offline';
  const evidence = (row.evidence_source ?? '').toLowerCase();
  if (evidence.includes('osv')) return 'osv';
  if (evidence.includes('npm audit')) return 'npm-audit';
  return '';
}
const changesOf = (data) => data.changes.findings ?? [];
const num = (key, label) => [key, label, (row) => count(row[key]), 'numeric'];
const code = (key, label) => [key, label, (row) => row[key] ? <code>{row[key]}</code> : '—'];
const advisoryId = ['id', 'Advisory or rule', (row) => /^https?:\/\//i.test(row.reference ?? '') ?
  <a href={row.reference} target="_blank" rel="noreferrer">{row.id}</a> : row.id];
const findingDetails = ['title', 'Finding', (row) => row.offline ? <>
  <div>{row.title}</div>
  <small className="muted"><code>{row.file}:{row.line}</code></small>
  {row.remediation && <details><summary>Remediation and context</summary>
    <p>{[row.cwe, row.kind, row.test_file && 'Test file'].filter(Boolean).join(' · ')}</p>
    <p>{row.remediation}</p>
  </details>}
</> : row.title];
const advisoryColumns = [
  advisoryId, ['source', 'Found by', (row) => <span className={'finding-source ' + findingSource(row)}
    title={row.evidence_source}>{sourceNames[findingSource(row)] ?? row.evidence_source ?? 'Unknown'}</span>],
  ['package', 'Package'], findingDetails, ['severity', 'Severity', (row) => row.offline ? '—' : <Severity value={row.severity} />],
  code('installed_version', 'Version'), code('fixed_version', 'Fixed in'),
  ['scope', 'Scope', (row) => row.offline ? '—' : capitalize(row.scope)],
  ['aliases', 'Aliases', (row) => row.aliases?.join(', ') || '—'],
  ['direct', 'Dependency', (row) => row.offline ? '—' : row.direct ? 'Direct' : 'Transitive'],
  code('affected_range', 'Affected range'),
  ['path', 'Dependency path', (row) => row.dependency_path?.join(' → ') || '—'],
];

function risk(data) {
  const findings = findingsOf(data);
  const changes = changesOf(data).filter((row) => row.kind === 'change');
  const affected = (scope, ...levels) => findings.filter((v) => allScopes(v, scope) && levels.includes(v.severity)).length;
  const changed = (...levels) => changes.filter((row) => levels.includes(row.severity)).length;
  const unpinned = (ecosystem, pin) => Number(data.infrastructure.some((c) => c.ecosystem === ecosystem && c.pinning !== pin));
  const deductions = [
    ['Critical advisories in shipped packages', affected('prod', 'critical'), 15],
    ['High advisories in shipped packages', affected('prod', 'high'), 6],
    ['Moderate advisories in shipped packages', affected('prod', 'moderate', 'medium'), 2],
    ['Low advisories in shipped packages', affected('prod', 'low'), 0.5],
    ['Critical or high advisories in dev-only packages', affected('dev', 'critical', 'high'), 1],
    ['Critical or high changes since baseline', changed('critical', 'high'), 10],
    ['Medium changes since baseline', changed('medium'), 4],
    ['Container images without a digest pin', unpinned('docker', 'digest'), 4],
    ['CI actions without a commit-SHA pin', unpinned('github-actions', 'sha'), 2],
  ].filter(([, items]) => items).map(([factor, items, points]) => ({ factor, items, points, deduction: items * points }));
  const score = Math.max(0, 100 - deductions.reduce((sum, row) => sum + row.deduction, 0));
  const [, grade, verdict] = [
    [90, 'A', 'Cleared'], [75, 'B', 'Cleared with notes'], [60, 'C', 'Inspect before shipping'],
    [40, 'D', 'Hold for review'], [0, 'F', 'Do not ship'],
  ].find(([threshold]) => score >= threshold);
  return { score, grade, verdict, deductions };
}

function priorityFindings(data) {
  const grouped = new Map();
  for (const row of findingsOf(data)) {
    if (severityRank(row.severity) > 1) continue;
    const key = packageId(row);
    const group = grouped.get(key) ?? { ...row, packageVersion: key, advisories: [] };
    if (severityRank(row.severity) < severityRank(group.severity)) group.severity = row.severity;
    group.advisories.push(row);
    grouped.set(key, group);
  }
  const changes = changesOf(data).filter((row) => row.kind === 'change' && severityRank(row.severity) < 2)
    .sort(bySeverity).map((row) => ({ ...row, key: row.id, section: 'changes', description: row.file }));
  const packages = [...grouped.values()].sort((a, b) =>
    Number(b.scope === 'prod') - Number(a.scope === 'prod') || bySeverity(a, b))
    .map((row) => ({
      ...row, key: row.packageVersion, section: 'vulnerabilities', title: row.packageVersion,
      description: [
        row.direct ? 'Direct dependency' : row.introduced_via?.slice(0, 2).join(', ') || 'Transitive dependency',
        count(row.advisories.length) + (row.advisories.length === 1 ? ' advisory' : ' advisories'),
      ].join(' · '),
    }));
  return [...changes, ...packages];
}

function PathLine({ path = [] }) {
  return path.length ? <ol className="path" aria-label="Dependency path">
    {path.map((label, index) => <li key={index}>{index > 0 && <ChevronRight size={14} aria-hidden="true" />}<code>{label}</code></li>)}
  </ol> : <Empty>No path from the project root was recorded.</Empty>;
}

export function Blank({ local, name, onAdd, onInspect, busy }) {
  return <Panel className="first-run">
    <ScanLine size={26} strokeWidth={1.5} aria-hidden="true" />
    <h2>{local ? 'Ready to inspect ' + name : 'Inspect your first repository'}</h2>
    <p className="muted">{local ? 'Run an inspection to generate the dependency inventory and evidence report.' :
      'Add a public GitHub repository with a package.json at its root.'}</p>
    <button className="primary" disabled={busy} onClick={local ? onInspect : onAdd}>
      {local ? 'Inspect repository' : 'Add repository'}
    </button>
  </Panel>;
}

export function Summary({ data }) {
  const { report } = data;
  const m = report.metrics;
  const severity = m.vulnerabilities_by_severity;
  const findings = findingsOf(data);
  const priority = priorityFindings(data);
  const grade = risk(data);
  const assessed = data.artifacts.includes('inventory.json') && data.artifacts.includes('vulnerability_findings.json')
    && data.artifacts.includes('suspicious_changes.json') && !report.errors?.length && Boolean(report.scanner);
  const impact = tally(findings.flatMap((row) => [...new Set(row.introduced_via ?? [])])).slice(0, 8);
  const affectedPackages = new Set(findings.map(packageId)).size;
  const online = Boolean(report.scanner);
  const metrics = [
    ['Installed packages', m.npm_packages, count(m.direct_dependencies) + ' direct · ' + count(m.transitive_dependencies) + ' transitive'],
    ['Known advisories', online ? m.vulnerabilities : null, online ? 'Across ' + count(affectedPackages) + ' package versions' : 'Advisory lookup unavailable'],
    ['Critical / high', online ? count(severity.critical ?? 0) + ' / ' + count(severity.high ?? 0) : null,
      online ? count(m.vulnerable_prod) + ' production advisories total' : 'Advisory lookup unavailable'],
    ['Baseline changes', m.suspicious_changes, 'Compared with ' + (data.changes.base_ref ?? 'HEAD')],
  ];
  return <div className="section-stack">
    <section className="metrics" aria-label="Inspection metrics">
      {metrics.map(([label, value, detail]) => <div key={label}><span>{label}</span>
        <strong>{typeof value === 'number' ? count(value) : value ?? '—'}</strong><small>{detail}</small></div>)}
    </section>
    <div className="overview-grid aligned">
      <Panel title="Needs attention first" action={<a href="#vulnerabilities">View advisories</a>}>
        {priority.length ? <ul className="findings">
          {priority.slice(0, 5).map((row) => <li key={row.key}>
            <div><a className="finding-name" href={'#' + row.section}>{row.title}</a><small>{row.description}</small></div>
            <Severity value={row.severity} />
          </li>)}
        </ul> : <Empty>No critical or high findings recorded.</Empty>}
      </Panel>
      <Panel title="Inspection grade" className="grade-panel">
        {assessed ? <>
          <div className="grade"><span className={'letter grade-' + grade.grade}>{grade.grade}</span>
            <div><strong>{grade.verdict}</strong><p className="muted">{count(grade.score)} of 100 points</p></div>
          </div>
          <div aria-hidden="true" className="grade-track"><span style={{ width: grade.score + '%' }} /></div>
          <details className="disclosure"><summary>How the grade is calculated</summary>
            <p className="muted">Start at 100 and subtract deductions. A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, otherwise F.</p>
            <Table rows={grade.deductions} empty="No deductions." columns={[
              ['factor', 'Risk factor'], num('items', 'Count'), num('points', 'Points each'), num('deduction', 'Deducted'),
            ]} />
          </details>
        </> : <Empty>A grade requires complete inventory, advisory and change findings.</Empty>}
        <h3>Advisories by severity</h3>
        <Bars rows={severities.filter((level) => severity[level]).map((level) => [capitalize(level), severity[level]])} severity />
      </Panel>
    </div>
    <div className="overview-grid aligned">
      <Panel title="Advisories by direct dependency"><Bars rows={impact} /></Panel>
      <Panel title="Dependency trace" action={<a href="#dependency-map">View map</a>}>
        {report.trace ? <>
          <p className="trace-title"><code>{report.trace.package}</code> <Severity value={report.trace.severity} /></p>
          <PathLine path={report.trace.shortest_path} />
          <dl className="trace-facts">
            <div><dt>Advisory</dt><dd><code>{report.trace.vulnerability}</code></dd></div>
            <div><dt>Scope</dt><dd>{report.trace.scope === 'prod' ? 'Production' : 'Development'}</dd></div>
            <div><dt>Fixed in</dt><dd>{report.trace.fixed_version ? <code>{report.trace.fixed_version}</code> : 'No version recorded'}</dd></div>
          </dl>
        </> : <Empty>No advisory trace recorded.</Empty>}
      </Panel>
    </div>
  </div>;
}

function PackageInventory({ value, data, graph }) {
  const packages = value.dependencies ?? [];
  const [query, setQuery] = useState('');
  const [scope, setScope] = useState('');
  const [kind, setKind] = useState('');
  const [selected, select] = useState('');
  const normalized = query.trim().toLowerCase();
  const rows = packages.filter((row) => row.name.toLowerCase().includes(normalized) &&
    allScopes(row, scope) && (!kind || row.type === kind));
  const detail = packages.filter((row) => row.name === selected);
  const related = [...findingsOf(data), ...offlineRows(data)].filter((row) => row.package === selected);
  const nodes = new Map((graph?.nodes ?? []).map((node) => [node.id, node]));
  const versions = new Map();
  for (const row of packages) {
    const installed = versions.get(row.name) ?? new Set();
    installed.add(row.version);
    versions.set(row.name, installed);
  }
  const duplicates = [...versions.entries()].filter(([, found]) => found.size > 1)
    .sort((a, b) => b[1].size - a[1].size).map(([pkg, found]) => ({ pkg, count: found.size, versions: [...found].sort().join(', ') }));
  return <div className="section-stack">
    <Panel title="Resolved packages">
      <div className="filters">
        <Search label="Package name" value={query} onChange={setQuery} placeholder="e.g. express" />
        <Select label="Dependency type" value={kind} onChange={setKind} options={[['', 'All types'], ['direct', 'Direct'], ['transitive', 'Transitive']]} />
        <Select label="Scope" value={scope} onChange={setScope} options={scopeOptions} />
      </div>
      <p className="muted">{count(rows.length)} of {count(packages.length)} entries</p>
      <Table key={JSON.stringify([query, scope, kind])} rows={rows} columns={[
        ['name', 'Package', (row) => <button className="text-button" aria-pressed={selected === row.name}
          onClick={() => select(row.name)}>{row.name}</button>],
        code('version', 'Version'), ['type', 'Dependency'], ['scope', 'Scope'], ['license', 'Licence'],
        code('declared_range', 'Declared range'), ['install', 'Install script', (row) => row.has_install_script ? 'Yes' : 'No'],
        code('lock_path', 'Lockfile path'),
      ]} />
    </Panel>
    {detail.length > 0 && <Panel title={selected} action={<button onClick={() => select('')}>Close details</button>}>
      <ul className="details-list">{detail.map((row) => <li key={row.lock_path}>
        <code>{row.version}</code> · {capitalize(row.scope)} · {capitalize(row.type)} · {row.license ?? 'Licence undeclared'}
        {row.has_install_script && ' · Has install script'}
        <PathLine path={nodes.get(row.lock_path)?.shortest_path} />
      </li>)}</ul>
      <h3>Findings for {selected}</h3>
      <Table rows={related} columns={advisoryColumns.slice(0, 7)} empty="No findings for this package." />
    </Panel>}
    <Panel title="Packages with multiple versions">
      <Table rows={duplicates} columns={[[ 'pkg', 'Package' ], num('count', 'Versions installed'), code('versions', 'Versions')]}
        empty="Every resolved package has a single version." />
    </Panel>
  </div>;
}

export function Packages({ name, data }) {
  const inventory = useArtifact(name, 'dependency_inventory.json', data);
  const graph = useArtifact(name, 'dependency_graph.json', data);
  return <Resource result={inventory}>{(value) => <PackageInventory value={value} data={data} graph={graph?.value} />}</Resource>;
}

function graphStats(graph, vulnerable) {
  const outgoing = new Map();
  for (const edge of graph.edges) {
    if (!outgoing.has(edge.from)) outgoing.set(edge.from, []);
    outgoing.get(edge.from).push(edge.to);
  }
  function unroll(root) {
    const ids = [root];
    const depth = new Map([[root, 0]]);
    for (const id of ids) {
      for (const next of outgoing.get(id) ?? []) {
        if (depth.has(next)) continue;
        ids.push(next);
        depth.set(next, depth.get(id) + 1);
      }
    }
    return depth;
  }
  const nodes = new Map(graph.nodes.map((node) => [node.id, node]));
  const depths = [...unroll('ROOT').values()].filter(Boolean);
  const leads = (outgoing.get('ROOT') ?? []).map((id) => {
    const members = unroll(id);
    return { label: nodes.get(id)?.label ?? id, size: members.size - 1, affected: [...members.keys()].some((node) => vulnerable.has(nodes.get(node)?.label)) };
  }).sort((a, b) => b.size - a.size);
  return { levels: tally(depths).sort((a, b) => a[0] - b[0]), leads };
}

function GraphView({ name, data, graph }) {
  const findings = findingsOf(data);
  const vulnerable = useMemo(() => new Set(findings.map(packageId)), [findings]);
  const stats = useMemo(() => graphStats(graph, vulnerable), [graph, vulnerable]);
  const [only, setOnly] = useState(vulnerable.size > 0);
  const [routes, setRoutes] = useState('1');
  const [pick, setPick] = useState('');
  const [tree, setTree] = useState(false);
  const [mapError, setMapError] = useState(false);
  const candidates = graph.nodes.filter((node) => node.id !== 'ROOT' && (!only || vulnerable.has(node.label)))
    .sort((a, b) => a.label.localeCompare(b.label));
  const target = candidates.find((node) => node.id === pick) ??
    candidates.find((node) => node.label === data.report.trace?.package) ?? candidates[0];
  const advisoryIds = [...new Set(findings.filter((row) => packageId(row) === target?.label).map((row) => row.id))];
  const paths = useResource(target ? repoUrl(name) + '/dependency-paths?node=' + encodeURIComponent(target.id) : null);
  return <div className="section-stack">
    <Panel title="Trace a package">
      <div className="filters">
        <Select label="Package" value={target?.id ?? ''} onChange={setPick}
          options={candidates.length ? candidates.map((node) => [node.id, node.label + (node.direct ? ' · direct' : ' · ' + node.id)]) : [['', 'No matching packages']]} />
        <label className="check"><input type="checkbox" checked={only} onChange={(event) => setOnly(event.target.checked)} />
          Only packages with advisories</label>
      </div>
      {target && <>
        {(paths?.value?.length ? paths.value : [target.shortest_path]).map((path, index) =>
          <PathLine path={path} key={index} />)}
        {paths?.error && <p className="muted">Additional paths could not be loaded.</p>}
        {target.introduced_via?.length > 0 && <p className="muted">Introduced by {target.introduced_via.join(', ')}</p>}
        {advisoryIds.length > 0 && <p>Advisories <code>{advisoryIds.join(', ')}</code></p>}
      </>}
    </Panel>
    <div className="overview-grid">
      <Panel title="Largest direct dependencies"><Table rows={stats.leads.slice(0, 12)} columns={[
        ['label', 'Dependency'], num('size', 'Packages added'), ['affected', 'Advisories', (row) => row.affected ? 'Present' : 'None known'],
      ]} /></Panel>
      <Panel title="Packages by depth"><Bars rows={stats.levels.map(([level, size]) => ['Level ' + level, size])} /></Panel>
    </div>
    <Panel title="Vulnerability paths" action={data.artifacts.includes('vulnerability_graph.svg') &&
      <DownloadLink name={name} file="vulnerability_graph.svg">Saved map</DownloadLink>}>
      {vulnerable.size ? <>
        <div className="filters"><Select label="Routes per vulnerable package" value={routes}
          onChange={(value) => { setRoutes(value); setMapError(false); }} options={['1', '2', '3'].map((n) => [n, n])} /></div>
        {mapError ? <p className="notice" role="alert">The vulnerability map could not be loaded.</p> : <img className="graph"
          src={repoUrl(name) + '/vulnerability-map?routes=' + routes}
          onError={() => setMapError(true)} alt="Radial dependency graph showing paths to vulnerable packages" />}
        <p className="muted">Red nodes have advisories. Orange paths show how those packages enter the tree.</p>
      </> : <Empty>No vulnerabilities are recorded in this tree.</Empty>}
    </Panel>
    {data.artifacts.includes('dependency_graph.html') && <Panel title="Full dependency tree"
      action={<DownloadLink name={name} file="dependency_graph.html">Download HTML</DownloadLink>}>
      <button aria-expanded={tree} onClick={() => setTree(!tree)}>{tree ? 'Hide tree browser' : 'Open tree browser'}</button>
      {tree && <iframe title="Full dependency tree browser" sandbox="allow-scripts"
        src={artifactUrl(name, 'dependency_graph.html') + '?inline=true'} />}
    </Panel>}
  </div>;
}

export function DependencyMap({ name, data }) {
  const graph = useArtifact(name, 'dependency_graph.json', data);
  return <Resource result={graph}>{(value) => <GraphView name={name} data={data} graph={value} />}</Resource>;
}


function fixBreakdown(findings) {
  const groups = new Map();
  for (const finding of findings) {
    const leads = finding.introduced_via?.length ? finding.introduced_via : [packageId(finding)];
    for (const lead of new Set(leads)) {
      const item = groups.get(lead) ?? { lead, advisories: 0, fixed: 0, severity: 'unknown', packages: new Set() };
      item.advisories += 1;
      item.fixed += Number(Boolean(finding.fixed_version));
      item.packages.add(packageId(finding));
      if (severityRank(finding.severity) < severityRank(item.severity)) item.severity = finding.severity;
      groups.set(lead, item);
    }
  }
  return [...groups.values()].sort((a, b) => b.advisories - a.advisories);
}

export function Vulnerabilities({ name, data }) {
  const [query, setQuery] = useState('');
  const [source, setSource] = useState('');
  const [levels, setLevels] = useState([]);
  const [scope, setScope] = useState('');
  const [fix, setFix] = useState('');
  const findings = findingsOf(data);
  const offline = data.report.offline_review;
  const rules = offlineRows(data);
  const recs = useArtifact(name, 'fix_recommendations.json', data);
  const term = query.trim().toLowerCase();
  const filtered = [...findings, ...rules].filter((row) => (!source || findingSource(row) === source) &&
    (!levels.length || levels.includes(row.severity)) && (!scope || !row.offline && allScopes(row, scope)) &&
    (!fix || !row.offline && Boolean(row.fixed_version) === (fix === 'available')) &&
    [row.package, row.id, row.file, ...(row.aliases ?? [])].some((value) =>
      value?.toLowerCase().includes(term))).sort(bySeverity);
  const sources = Object.entries(sourceNames).filter(([key]) => key !== 'npm-audit' ||
    findings.some((row) => findingSource(row) === key) || data.report.scanner === key);
  const availableLevels = severities.filter((severity) => findings.some((row) => row.severity === severity));
  return <div className="section-stack">
    <Panel title="Vulnerability findings" action={<div className="actions">
      {data.artifacts.includes('vulnerability_findings.json') &&
        <DownloadLink name={name} file="vulnerability_findings.json">Advisory JSON</DownloadLink>}
      {offline && data.artifacts.includes('dependency_review.json') &&
        <DownloadLink name={name} file="dependency_review.json">Offline evidence</DownloadLink>}
    </div>}>
      <div className="finding-coverage">
        <div><strong>{sourceNames[data.report.scanner] ?? 'Advisory lookup'}</strong>
          <p className="muted">{data.report.scanner ? count(findings.length) + ' advisories' : 'Unavailable for this inspection.'}</p>
          {(data.report.scanner_notes ?? []).map((note, index) => <p className="muted" key={index}>{note}</p>)}
        </div>
        <div><strong>Offline rules</strong>
          <p className="muted">{!offline ? 'Run a new inspection to review dependency code.' : offline.status === 'error' ?
            offline.message : count(rules.length) + ' matches · ' + count(offline.coverage.packages_reviewed) +
            ' of ' + count(offline.coverage.packages) + ' dependencies reviewed (' + offline.status + ' coverage)'}</p>
        </div>
      </div>
      <div className="filters">
        <Search label="Package, advisory, rule or file" value={query} onChange={setQuery} placeholder="e.g. crypto-js" />
        <Select label="Found by" value={source} onChange={(value) => {
          setSource(value);
          if (value === 'offline') { setLevels([]); setScope(''); setFix(''); }
        }} options={[[ '', 'All sources' ], ...sources]} />
        {source !== 'offline' && <>
          <Select label="Scope" value={scope} onChange={setScope} options={scopeOptions} />
          <Select label="Fix availability" value={fix} onChange={setFix}
            options={[['', 'All findings'], ['available', 'Fixed version available'], ['missing', 'No fixed version published']]} />
        </>}
      </div>
      {source !== 'offline' && availableLevels.length > 0 && <fieldset className="severity-filters">
        <legend>Severity · {levels.length ? 'Selected levels' : 'All levels'}</legend>
        {availableLevels.map((level) => <label className="check" key={level}>
          <input type="checkbox" checked={levels.includes(level)} onChange={(event) => setLevels(
            event.target.checked ? [...levels, level] : levels.filter((item) => item !== level)
          )} />{capitalize(level)}
        </label>)}
      </fieldset>}
      <p className="muted">{count(filtered.length)} of {count(findings.length + rules.length)} findings</p>
      <Table key={JSON.stringify([source, scope, fix, query, levels])} rows={filtered}
        columns={source === 'offline' ? advisoryColumns.filter(([key]) =>
          ['id', 'source', 'package', 'title', 'installed_version'].includes(key)) : advisoryColumns}
        empty="No matching findings." />
      {rules.length > 0 && source !== 'offline' && <p className="muted">Severity, scope and fix filters apply to advisories.</p>}
      {source !== 'offline' && findings.some((row) => row.fixed_version_source?.startsWith('derived')) &&
        <p className="muted">Some fixed versions were derived from the advisory’s affected range.</p>}
    </Panel>
    {source !== 'offline' && <><Panel title="Fix availability by direct dependency">
      <Table rows={fixBreakdown(findings)} columns={[
        ['lead', 'Direct dependency'], ['severity', 'Worst severity', (row) => <Severity value={row.severity} />],
        num('advisories', 'Advisories'), num('fixed', 'With a fix'),
        ['packages', 'Affected packages', (row) => [...row.packages].sort().join(', ')],
      ]} empty="No advisory paths recorded." />
    </Panel>
    <Panel title="Fix recommendations" action={data.artifacts.includes('fix_recommendations.csv') &&
      <DownloadLink name={name} file="fix_recommendations.csv">Download CSV</DownloadLink>}>
      <Resource result={recs} missing="No fix recommendations were generated.">
        {(rows) => rows.length ? <div className="disclosures">{rows.map((row) => <details key={packageId(row)}>
          <summary><span className="inline">{row.priority.split(' ')[0]} <code>{packageId(row)}</code> {row.action}
            <Severity value={row.worst_severity} /></span></summary>
          <p>{row.headline}</p>
          <ul>{row.steps.map((step, index) => <li key={index}>{step}</li>)}</ul>
          <p className="muted">{row.ids.join(', ')} · {row.source}</p>
        </details>)}</div> : <Empty>No fix recommendations were generated.</Empty>}
      </Resource>
    </Panel>
    </>}
  </div>;
}

function ChangeList({ rows, empty }) {
  if (!rows.length) return <Empty>{empty}</Empty>;
  return <div className="disclosures">{rows.map((row, index) => <details key={row.id ?? index}>
    <summary><span className="inline"><Severity value={row.severity} />{row.title}</span></summary>
    <p><code>{row.file}</code></p>
    <p>{row.why_suspicious}</p>
    {row.kind === 'change' && (row.before != null || row.after != null) && <div className="comparison">
      <div><h3>Before</h3><pre>{row.before ?? '(not present)'}</pre></div>
      <div><h3>After</h3><pre>{row.after ?? '(not present)'}</pre></div>
    </div>}
    {row.evidence && Object.keys(row.evidence).length > 0 && <pre>{JSON.stringify(row.evidence, null, 2)}</pre>}
  </details>)}</div>;
}

export function Changes({ data }) {
  const rows = changesOf(data);
  if (!data.artifacts.includes('suspicious_changes.json')) return <Empty>No change report was generated.</Empty>;
  return <div className="section-stack">
    <Panel title="Changes since baseline">
      <p className="muted">Compared with <code>{data.changes.base_ref ?? 'HEAD'}</code></p>
      {(data.changes.notes ?? []).map((note, index) => <p className="muted" key={index}>{note}</p>)}
      <ChangeList rows={rows.filter((row) => row.kind === 'change')} empty="No supply chain changes recorded since this baseline." />
    </Panel>
    <Panel title="Standing observations">
      <ChangeList rows={rows.filter((row) => row.kind === 'baseline')} empty="No standing observations recorded." />
    </Panel>
  </div>;
}

const licenceGroups = [
  ['Strong copyleft', ['AGPL', 'GPL', 'CC-BY-SA', 'EUPL', 'SSPL', 'OSL']],
  ['Weak copyleft', ['LGPL', 'MPL', 'EPL', 'CDDL', 'CPL']],
  ['Permissive', ['MIT', 'ISC', 'APACHE', 'BSD', '0BSD', 'BLUEOAK', 'UNLICENSE', 'CC0',
    'PYTHON', 'ZLIB', 'WTFPL', 'ARTISTIC', 'CC-BY', 'OFL', 'BOOST', 'X11']],
];

function licenceGroup(value) {
  const licence = value?.trim().toUpperCase();
  if (!licence || ['NONE', 'UNLICENSED'].includes(licence) || licence.includes('SEE LICENSE')) return 'Not declared';
  return licenceGroups.find(([, prefixes]) => prefixes.some((p) =>
    licence.startsWith(p) || licence.includes('(' + p) || licence.includes(' ' + p)))?.[0] ?? 'Other';
}

export function Licence({ name, data }) {
  const inventory = useArtifact(name, 'dependency_inventory.json', data);
  return <Resource result={inventory}>{(value) => {
    const rows = value.dependencies.map((row) => ({ ...row, group: licenceGroup(row.license) }));
    const flagged = rows.filter((row) => row.group !== 'Permissive')
      .sort((a, b) => a.group.localeCompare(b.group) || a.name.localeCompare(b.name));
    return <div className="section-stack">
      <div className="overview-grid">
        <Panel title="Licence groups"><Bars rows={tally(rows.map((row) => row.group))} /></Panel>
        <Panel title="Most common licences"><Bars rows={tally(rows.map((row) => row.license || 'Not declared')).slice(0, 12)} /></Panel>
      </div>
      <Panel title="Packages to review">
        <p className="muted">{count(flagged.filter((row) => row.scope === 'prod').length)} production entries have a copyleft, other or undeclared licence.</p>
        <Table rows={flagged} columns={[['name', 'Package'], code('version', 'Version'),
          ['group', 'Group'], ['license', 'Licence'], ['type', 'Dependency'], ['scope', 'Scope']]} />
      </Panel>
    </div>;
  }}</Resource>;
}

export function Sbom({ name, data }) {
  const bom = useArtifact(name, data.sbomFile, data);
  const info = data.report.sbom;
  return <Panel title={info ? info.format + ' ' + info.spec_version : 'Software bill of materials'}
    action={data.sbomFile && <DownloadLink name={name} file={data.sbomFile}>Download SBOM</DownloadLink>}>
    {info && <>
      <p>Generated by <strong>{info.tool}</strong> with {count(info.component_count)} components.
        {' '}{count(info.matched_inventory)} of {count(info.npm_component_count)} npm components match the inventory.</p>
      {info.note && <p className="muted">{info.note}</p>}
    </>}
    <Resource result={bom} missing="There is no SBOM file for this inspection.">
      {(value) => <Table rows={value.components ?? []} columns={[
        ['name', 'Component', (row) => [row.group, row.name].filter(Boolean).join('/')],
        code('version', 'Version'), ['type', 'Type'], code('purl', 'Package URL'),
      ]} empty="This SBOM contains no components." />}
    </Resource>
  </Panel>;
}

export function Run({ name, data, job, busy }) {
  const recent = job && (!job.repository || job.repository === name || busy) ? job : null;
  const showLive = recent && (recent.status !== 'complete' || !data?.report);
  const log = showLive ? recent.log : data?.report?.agent_log ?? [];
  const hasHistory = !busy && data?.artifacts.includes('history.jsonl');
  const history = useResource(hasHistory ? repoUrl(name) + '/history' : null);
  return <div className="section-stack">
    {(recent || data?.report) ? <Panel title={recent?.status === 'running' ? 'Inspection in progress' : 'Inspection workflow'}>
      {recent?.status === 'running' && <p className="muted" role="status">Waiting for the next workflow update…</p>}
      {recent?.error && <p className="notice" role="alert">{recent.error}</p>}
      {recent?.status === 'complete' && <p className="muted" role="status">Inspection complete.</p>}
      {log.length > 0 && <ol className="workflow">
        {log.map((entry, index) => <li key={index}>
          <span className={'workflow-icon ' + entry.status} aria-hidden="true">
            {entry.status === 'ok' ? <Check size={16} /> : entry.status === 'error' ? <CircleAlert size={16} /> : <GitBranch size={16} />}
          </span>
          <div><strong>{entry.agent}</strong><p>{entry.message}</p></div>
          {entry.status !== 'info' && <span className="step-status">{entry.status === 'ok' ? 'Done' : capitalize(entry.status)}</span>}
        </li>)}
      </ol>}
      {!busy && (data?.report?.scanner_notes ?? []).map((note, index) =>
        <p className="muted" key={index}>Advisory lookup · {note}</p>)}
      {!busy && (data?.report?.errors ?? []).map((error, index) => <p className="notice" key={index}>{error}</p>)}
    </Panel> : <Panel title="Inspection workflow"><Empty>No inspection run recorded.</Empty></Panel>}
    {hasHistory && <Panel title="Inspection history">
      <Resource result={history}>{(value) => <>
        <Table rows={[...value].reverse()} columns={[
          ['at', 'Inspected', (row) => timestamp(row.at)], ['commit', 'Commit', (row) => <code>{row.commit?.slice(0, 9) || '—'}</code>],
          code('base_ref', 'Baseline'), num('npm_packages', 'Packages'), num('vulnerabilities', 'Advisories'),
          ['critical', 'Critical', (row) => count(row.by_severity?.critical ?? 0), 'numeric'],
          ['high', 'High', (row) => count(row.by_severity?.high ?? 0), 'numeric'], num('suspicious_changes', 'Changes'),
        ]} empty="No inspection history recorded." />
        {value.length > 1 && <><h3>Advisories in recent inspections</h3>
          <Bars rows={value.slice(-8).map((row, index, recentRows) =>
            ['Run ' + (value.length - recentRows.length + index + 1), row.vulnerabilities])} /></>}
      </>}</Resource>
    </Panel>}
  </div>;
}

export function Repositories({ repos, selectRepo, busy }) {
  const inspected = repos.filter((row) => row.metrics);
  return <div className="section-stack"><Panel title="Repository inventory">
    <Table rows={repos} columns={[
      ['name', 'Repository', (row) => <button className="text-button" disabled={busy} onClick={() => selectRepo(row.name)}>{row.name}</button>],
      ['inspected', 'Last inspection', (row) => timestamp(row.inspected)],
      ['packages', 'Packages', (row) => count(row.metrics?.npm_packages), 'numeric'],
      ['advisories', 'Advisories', (row) => count(row.metrics?.vulnerabilities), 'numeric'],
      ['critical', 'Critical', (row) => count(row.metrics ? row.metrics.vulnerabilities_by_severity.critical ?? 0 : null), 'numeric'],
      ['high', 'High', (row) => count(row.metrics ? row.metrics.vulnerabilities_by_severity.high ?? 0 : null), 'numeric'],
      ['changes', 'Changes', (row) => count(row.metrics?.suspicious_changes), 'numeric'],
      ['local', 'Source', (row) => row.local ? 'Local clone' : 'Saved report'],
    ]} empty="No repositories have been added." />
  </Panel>
    {inspected.length > 1 && <div className="overview-grid">
      {['critical', 'high'].map((severity) => <Panel key={severity} title={capitalize(severity) + ' advisories by repository'}>
        <Bars rows={inspected.map((row) => [row.name, row.metrics.vulnerabilities_by_severity[severity] ?? 0])} />
      </Panel>)}
    </div>}
  </div>;
}

export function Report({ name, data }) {
  const interpretation = data.report.interpretation;
  return <div className="section-stack">
    <Panel title="Evidence report">
      {interpretation?.source && <p className="muted">Written by {interpretation.source}</p>}
      {interpretation?.text ? <div className="report-copy"><Markdown>{interpretation.text}</Markdown></div> :
        <Empty>No written interpretation was generated.</Empty>}
    </Panel>
    <Panel title="Download evidence">
      <div className="actions">
        <DownloadLink name={name} file="bundle.zip">All results (ZIP)</DownloadLink>
        {data.artifacts.includes('evidence_report.md') && <DownloadLink name={name} file="evidence_report.md">Markdown</DownloadLink>}
        <DownloadLink name={name} file="evidence_report.json">Report JSON</DownloadLink>
      </div>
    </Panel>
  </div>;
}

