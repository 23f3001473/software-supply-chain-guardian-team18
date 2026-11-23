import { useEffect, useState } from 'react';
import { Download } from 'lucide-react';

export const severities = ['critical', 'high', 'moderate', 'medium', 'low', 'info', 'unknown'];
export const scopeOptions = [['', 'All scopes'], ['prod', 'Production'], ['dev', 'Development only']];
export const repoUrl = (name) => '/api/repositories/' + encodeURIComponent(name);
export const artifactUrl = (name, file) => repoUrl(name) + '/artifacts/' + encodeURIComponent(file);
export const count = (value) => value == null ? '—' : Number(value).toLocaleString();
export const capitalize = (value) => value ? value[0].toUpperCase() + value.slice(1) : 'Unknown';
export const packageId = (row) => row.package + '@' + row.installed_version;
export const severityRank = (severity) => {
  const rank = severities.indexOf(severity);
  return rank < 0 ? severities.length : rank;
};
export const bySeverity = (a, b) => severityRank(a.severity) - severityRank(b.severity);
export const timestamp = (iso) => iso ? new Date(iso).toLocaleString(undefined, {
  dateStyle: 'medium', timeStyle: 'short',
}) : '—';

export async function request(path, options) {
  const response = await fetch(path, { cache: 'no-store', ...options });
  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    const failure = new Error(typeof error.detail === 'string' ? error.detail : 'Request failed (' + response.status + ').');
    failure.status = response.status;
    throw failure;
  }
  return response.json();
}

export function useResource(url) {
  const [result, setResult] = useState(null);
  useEffect(() => {
    if (!url) return;
    const controller = new AbortController();
    request(url, { signal: controller.signal })
      .then((value) => setResult({ url, value }))
      .catch((error) => {
        if (!controller.signal.aborted) setResult({ url, error: error.message });
      });
    return () => controller.abort();
  }, [url]);
  return result?.url === url ? result : null;
}

export function Panel({ title, action, children, className = '' }) {
  return <section className={'panel ' + className}>
    {(title || action) && <div className="panel-head"><h2>{title}</h2>{action}</div>}
    {children}
  </section>;
}

export function Empty({ children }) {
  return <p className="empty">{children}</p>;
}

export function Severity({ value }) {
  return <span className={'severity ' + value}>{capitalize(value)}</span>;
}

export function DownloadLink({ name, file, children }) {
  return <a className="button" href={artifactUrl(name, file)} download><Download size={15} />{children}</a>;
}

export function Select({ label, value, onChange, options, disabled }) {
  return <label className="field"><span>{label}</span>
    <select disabled={disabled} value={value} onChange={(event) => onChange(event.target.value)}>
      {options.map(([key, text]) => <option key={key} value={key}>{text}</option>)}
    </select>
  </label>;
}

export function Search({ label = 'Search', value, onChange, placeholder }) {
  return <label className="field search"><span>{label}</span>
    <input type="search" value={value} onChange={(event) => onChange(event.target.value)} placeholder={placeholder} />
  </label>;
}

export function Resource({ result, missing = 'This artifact is unavailable.', children }) {
  if (result?.error) return <p className="notice" role="alert">{result.error}</p>;
  if (!result) return <Empty>Loading artifact…</Empty>;
  return result.value ? children(result.value) : <Empty>{missing}</Empty>;
}

export function Table({ columns, rows, rowKey, limit = 12, empty = 'No matching entries.' }) {
  const [page, setPage] = useState(0);
  const totalPages = Math.max(1, Math.ceil(rows.length / limit));
  const current = Math.min(page, totalPages - 1);
  if (!rows.length) return <Empty>{empty}</Empty>;
  return <>
    <div className="table-scroll" tabIndex={0} role="region" aria-label="Results table">
      <table>
        <thead><tr>{columns.map(([key, label, , type]) => <th key={key} scope="col" className={type}>{label}</th>)}</tr></thead>
        <tbody>{rows.slice(current * limit, (current + 1) * limit).map((row, index) =>
          <tr key={rowKey?.(row) ?? index}>{columns.map(([key, , render, type]) =>
            <td key={key} className={type}>{render ? render(row) : row[key] ?? '—'}</td>
          )}</tr>
        )}</tbody>
      </table>
    </div>
    {totalPages > 1 && <div className="pager">
      <span>{count(current * limit + 1)}–{count(Math.min((current + 1) * limit, rows.length))} of {count(rows.length)}</span>
      <div className="actions">
        <button disabled={current === 0} onClick={() => setPage(current - 1)}>Previous</button>
        <button disabled={current + 1 === totalPages} onClick={() => setPage(current + 1)}>Next</button>
      </div>
    </div>}
  </>;
}

export function Bars({ rows, severity = false }) {
  const max = Math.max(1, ...rows.map(([, value]) => value));
  if (!rows.length) return <Empty>No data recorded.</Empty>;
  return <ul className="bars">{rows.map(([label, value]) =>
    <li key={label} className={severity ? label.toLowerCase() : ''}>
      <span title={label}>{label}</span>
      <div className="bar-track" aria-hidden="true"><span style={{ width: (value / max * 100) + '%' }} /></div>
      <strong>{count(value)}</strong>
    </li>
  )}</ul>;
}

export function useArtifact(name, file, data) {
  const url = data.artifacts.includes(file) ? artifactUrl(name, file) : null;
  const result = useResource(url);
  return url ? result : { value: null };
}

export function tally(values) {
  const map = new Map();
  for (const value of values) map.set(value, (map.get(value) ?? 0) + 1);
  return [...map.entries()].sort((a, b) => b[1] - a[1]);
}

