import io
import json
import subprocess
import zipfile
from collections import Counter, defaultdict
from datetime import datetime
from html import escape
from pathlib import Path

import altair as alt
import networkx as nx
import pandas as pd
import streamlit as st

from guardian import vuln_graph
from guardian.repo_fetch import FetchError, fetch, out_dir_for
from guardian.workflow import run_stream

ROOT = Path(__file__).parent
TARGETS = ROOT / "target"

INK, STEEL, LINE, PAPER = "#1B2A3A", "#5E6E7E", "#D3DBE2", "#F4F6F7"
BLUE, RED, AMBER, GREEN = "#1F5FAE", "#B3261E", "#C98A00", "#2E7D5B"
SEVERITIES = ["critical", "high", "moderate", "medium", "low", "info", "unknown"]
SEV_COLOR = {"critical": RED, "high": "#D9622B", "moderate": AMBER, "medium": AMBER, "low": BLUE,
             "info": STEEL, "unknown": "#9AA7B3"}
AGENTS = ["1. Repository Discovery Agent", "2. SBOM Agent", "3. Dependency Analysis Agent",
          "4. Vulnerability Detection Agent", "5. Anomaly Detection Agent"]
SECTIONS = ["Summary", "Packages", "Dependency map", "Vulnerabilities", "Changes", "Licences", "SBOM",
            "Agent run", "All repositories", "Report"]

st.set_page_config(page_title="Guardian · supply chain inspection", page_icon="🛡️", layout="wide")

CSS = f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=Archivo:wdth,wght@62..125,400..800&family=JetBrains+Mono:wght@400;600&display=swap');
html, body, .stApp, .stMarkdown p, .stMarkdown li, label, input, textarea, [data-testid="stWidgetLabel"] p,
[data-testid="stMarkdownContainer"] p {{ font-family: 'Archivo', 'Segoe UI', system-ui, -apple-system, Helvetica, Arial, sans-serif; }}
.stApp {{ color: {INK}; }}
h1, h2, h3 {{ font-family: 'Archivo', system-ui, sans-serif !important; font-stretch: 80%; letter-spacing: -0.005em; color: {INK}; }}
h1 {{ font-weight: 800 !important; font-size: 2.6rem !important; line-height: 1.05 !important; padding: 0 !important; }}
h2 {{ font-weight: 750 !important; font-size: 1.55rem !important; margin-top: .6rem !important; }}
h3 {{ font-weight: 700 !important; font-size: 1.12rem !important; }}
code, .mono {{ font-family: 'JetBrains Mono', ui-monospace, Consolas, monospace !important; font-size: .84em;
              color: {INK} !important; background: #E8EDF1 !important; border-radius: 3px; padding: 1px 5px; }}
.block-container {{ padding-top: 2.2rem; max-width: 1320px; }}
[data-testid="stSidebar"] {{ background: #E8EDF1; border-right: 1px solid {LINE}; }}
.stButton > button, .stDownloadButton > button {{ border-radius: 4px; font-weight: 600; }}
.stMarkdown p.wordmark {{ font-stretch: 70%; font-weight: 800; font-size: 2.1rem !important; line-height: 1 !important;
                         color: {INK}; margin: 0 0 .2rem !important; letter-spacing: -.01em; }}
.stMarkdown p.wordmark-sub {{ color: {STEEL}; font-size: .88rem !important; margin: 0 0 1.1rem !important; line-height: 1.3; }}
.repo-kicker {{ color: {STEEL}; font-size: .95rem; margin-bottom: .2rem; }}
.manifest {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 0;
            border-top: 3px solid {INK}; border-bottom: 1px solid {LINE}; margin: .6rem 0 1.6rem; }}
.manifest > div {{ padding: .7rem 1rem .8rem 0; border-right: 1px solid {LINE}; margin-right: 1rem; }}
.manifest > div:last-child {{ border-right: none; }}
.manifest .k {{ color: {STEEL}; font-size: .8rem; }}
.manifest .v {{ font-size: 1.45rem; font-weight: 700; font-stretch: 82%; margin-top: .15rem; }}
.manifest .v small {{ display: block; font-size: .78rem; font-weight: 500; color: {STEEL}; font-stretch: 100%;
                      white-space: normal; line-height: 1.3; margin-top: .1rem; }}
.manifest .v.red {{ color: {RED}; }}
.stamp-wrap {{ display: flex; align-items: center; gap: 2.2rem; flex-wrap: wrap; margin: .2rem 0 1.4rem; }}
.stamp {{ --c: {RED}; display: inline-flex; align-items: center; gap: .9rem; color: var(--c);
         border: 4px solid var(--c); border-radius: 8px; padding: .55rem 1.2rem .55rem .9rem;
         box-shadow: inset 0 0 0 3px {PAPER}, inset 0 0 0 5px var(--c); transform: rotate(-3.5deg);
         background: rgba(255,255,255,.35); animation: thump .45s cubic-bezier(.2,1.6,.4,1) 1; }}
.stamp .grade {{ font-size: 4.2rem; font-weight: 800; font-stretch: 62%; line-height: .9; }}
.stamp .verdict {{ font-size: 1.15rem; font-weight: 800; font-stretch: 70%; text-transform: uppercase;
                  letter-spacing: .08em; line-height: 1.1; }}
.stamp .verdict span {{ display: block; font-size: .72rem; letter-spacing: .04em; font-weight: 600; opacity: .85; }}
@keyframes thump {{ from {{ transform: rotate(-3.5deg) scale(1.6); opacity: 0; }} to {{ transform: rotate(-3.5deg) scale(1); opacity: 1; }} }}
@media (prefers-reduced-motion: reduce) {{ .stamp {{ animation: none; }} }}
.verdict-text {{ max-width: 62ch; font-size: 1.05rem; line-height: 1.55; }}
.attention {{ list-style: none; padding: 0; margin: 0; }}
.attention li {{ display: grid; grid-template-columns: 5rem 1fr; gap: .8rem; padding: .62rem 0;
                border-bottom: 1px solid {LINE}; line-height: 1.45; }}
.sev {{ font-size: .78rem; font-weight: 700; padding: .12rem .5rem; border-radius: 3px; color: #fff;
        justify-self: start; align-self: start; margin-top: .1rem; }}
.note {{ color: {STEEL}; font-size: .88rem; }}
.swatch {{ display: inline-block; width: .75rem; height: .75rem; border-radius: 2px; margin: 0 .3rem 0 .9rem; vertical-align: -1px; }}
</style>
"""
st.markdown(CSS, unsafe_allow_html=True)


def altair_theme():
    return {"config": {"font": "Archivo, Segoe UI, Helvetica, Arial, sans-serif", "view": {"stroke": None},
                       "axis": {"labelColor": STEEL, "titleColor": STEEL, "gridColor": "#E3E8ED",
                                "domainColor": LINE, "tickColor": LINE, "labelFontSize": 11},
                       "legend": {"labelColor": STEEL, "titleColor": STEEL}}}


if hasattr(alt, "theme") and hasattr(alt.theme, "register"):
    alt.theme.register("guardian", enable=True)(altair_theme)
else:
    alt.themes.register("guardian", altair_theme)
    alt.themes.enable("guardian")


# ---------------- data helpers ----------------
def load(out: Path, name: str):
    p = out / name
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


def list_repos() -> list[Path]:
    if not TARGETS.exists():
        return []
    return sorted(p for p in TARGETS.iterdir() if (p / "package.json").exists())


def recent_commits(repo: Path, limit: int = 200) -> list[tuple[str, str]]:
    proc = subprocess.run(["git", "-C", str(repo), "log", f"-n{limit}", "--date=short", "--format=%h|%ad|%s"],
                          capture_output=True, text=True, encoding="utf-8", errors="replace")
    rows = []
    for k, line in enumerate(proc.stdout.splitlines()):
        sha, date, subject = (line.split("|", 2) + ["", ""])[:3]
        label = "Latest commit (uncommitted changes only)" if k == 0 else f"{k} commits back, {date}: {subject[:55]}"
        rows.append((label, "HEAD" if k == 0 else sha))
    return rows or [("Latest commit (uncommitted changes only)", "HEAD")]


def when(iso: str) -> str:
    try:
        return datetime.fromisoformat(iso).strftime("%d %b %Y, %H:%M UTC")
    except (TypeError, ValueError):
        return iso or "—"


def show_html(html: str, height: int):
    if hasattr(st, "iframe"):
        st.iframe(html, height=height)
    else:
        import streamlit.components.v1 as components
        components.html(html, height=height, scrolling=True)


@st.cache_data
def load_graph(path: str, mtime: float):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    g = nx.DiGraph()
    for n in data["nodes"]:
        g.add_node(n["id"], **{k: n[k] for k in ("label", "name", "version", "direct", "scope")})
    g.add_edges_from((e["from"], e["to"]) for e in data["edges"])
    return g, {n["id"]: n for n in data["nodes"]}


@st.cache_data
def graph_stats(path: str, mtime: float):
    g, _ = load_graph(path, mtime)
    depth = nx.single_source_shortest_path_length(g, "ROOT")
    size = {n: len(nx.descendants(g, n)) for n in g.successors("ROOT")}
    return depth, size


def paths_dot(g: nx.DiGraph, paths: list, target: str, vulnerable: set) -> str:
    keep = {n for p in paths for n in p}
    lines = ['digraph G { rankdir=LR; nodesep=0.25; bgcolor="transparent"; node [shape=box, style="rounded,filled", '
             'fontname="Helvetica", fontsize=11, fontcolor=white, penwidth=0];']
    for n in keep:
        d = g.nodes[n]
        color = INK if n == "ROOT" else RED if n == target else \
            "#D9622B" if d["label"] in vulnerable else BLUE if d.get("direct") else STEEL
        lines.append(f'"{n}" [label="{d["label"]}", fillcolor="{color}"];')
    edges = {(a, b) for p in paths for a, b in zip(p, p[1:])}
    lines += [f'"{a}" -> "{b}" [color="{STEEL}"];' for a, b in edges]
    return "\n".join(lines + ["}"])


def pipeline_dot(log: list) -> str:
    status = {e["agent"]: e["status"] for e in log}
    fill = {"ok": GREEN, "error": RED, "skipped": "#9AA7B3"}
    nodes = ["start"] + AGENTS + ["report", "end"]
    lines = ['digraph P { rankdir=LR; bgcolor="transparent"; node [shape=box, style="rounded,filled", '
             'fontname="Helvetica", fontsize=11, fontcolor=white, penwidth=0];']
    for n in nodes:
        key = next((k for k in status if k.startswith(n) or (n == "report" and k.startswith("Report"))), None)
        lines.append(f'"{n}" [fillcolor="{INK if n in ("start", "end") else fill.get(status.get(key), STEEL)}"];')
    lines += [f'"{a}" -> "{b}" [color="{STEEL}"];' for a, b in zip(nodes, nodes[1:])]
    return "\n".join(lines + ["}"])


def mono(text) -> str:
    return f"<code>{escape(str(text))}</code>"


def sev_badge(sev: str) -> str:
    return f'<span class="sev" style="background:{SEV_COLOR.get(sev, STEEL)}">{escape(sev)}</span>'


def section_title(title: str, note: str = ""):
    st.markdown(f"## {title}")
    if note:
        st.markdown(f'<p class="note">{note}</p>', unsafe_allow_html=True)


def bar(df, x, y, color=BLUE, height=260, sort="-x", color_enc=None):
    enc = color_enc if color_enc is not None else alt.value(color)
    return alt.Chart(df).mark_bar(cornerRadiusEnd=2).encode(
        x=alt.X(f"{x}:Q", title=None),
        y=alt.Y(f"{y}:N", sort=sort, title=None, axis=alt.Axis(labelOverlap=False, labelLimit=280)),
        color=enc, tooltip=list(df.columns)).properties(height=height)


# ---------------- risk grade (transparent, from real findings only) ----------------
def risk_grade(vdf: pd.DataFrame, changes: list, inventory: dict):
    rows = []

    def add(factor, count, each):
        if count:
            rows.append({"factor": factor, "count": int(count), "points each": each,
                         "deducted": round(count * each, 1)})
    prod = vdf[vdf.scope == "prod"] if not vdf.empty else vdf
    dev = vdf[vdf.scope != "prod"] if not vdf.empty else vdf
    if not vdf.empty:
        add("Critical advisories in shipped packages", (prod.severity == "critical").sum(), 15)
        add("High advisories in shipped packages", (prod.severity == "high").sum(), 6)
        add("Moderate advisories in shipped packages", prod.severity.isin(["moderate", "medium"]).sum(), 2)
        add("Low advisories in shipped packages", (prod.severity == "low").sum(), 0.5)
        add("Critical/high advisories in dev-only packages", dev.severity.isin(["critical", "high"]).sum(), 1)
    add("Critical/high changes since baseline", sum(f["severity"] in ("critical", "high") for f in changes), 10)
    add("Medium changes since baseline", sum(f["severity"] == "medium" for f in changes), 4)
    docker = [c for c in inventory["components"] if c["ecosystem"] == "docker"]
    actions = [c for c in inventory["components"] if c["ecosystem"] == "github-actions"]
    add("Container images without a digest pin", int(any(c["pinning"] != "digest" for c in docker)), 4)
    add("CI actions without a commit-SHA pin", int(any(c["pinning"] != "sha" for c in actions)), 2)
    score = max(0.0, 100 - sum(r["deducted"] for r in rows))
    for limit, letter, verdict, color in ((90, "A", "Cleared", GREEN), (75, "B", "Cleared with notes", GREEN),
                                          (60, "C", "Inspect before shipping", AMBER),
                                          (40, "D", "Hold for review", "#D9622B"), (0, "F", "Do not ship", RED)):
        if score >= limit:
            return round(score), letter, verdict, color, pd.DataFrame(rows)


# ---------------- scanning ----------------
def scan(repo: Path, base_ref: str, scanner: str, status) -> bool:
    status.write(f"Inspecting {repo.name} with 5 agents")
    final = None
    for kind, item in run_stream(str(repo), str(out_dir_for(repo)), base_ref, scanner):
        if kind == "log":
            word = {"ok": "Done", "error": "Failed", "skipped": "Skipped"}.get(item.status, item.status)
            status.write(f"**{item.agent}** — {word}. {item.message}")
        else:
            final = item
    st.cache_data.clear()
    if final and final.get("errors"):
        status.update(label="Inspection finished with errors", state="error", expanded=True)
        return False
    status.update(label=f"Inspection complete: {repo.name}", state="complete", expanded=False)
    return True


# ---------------- sidebar ----------------
st.sidebar.markdown('<p class="wordmark">Guardian</p><p class="wordmark-sub">Software supply chain inspection</p>',
                    unsafe_allow_html=True)

with st.sidebar.expander("Add a repository from GitHub", expanded=not list_repos()):
    url = st.text_input("Public repository link", placeholder="https://github.com/owner/repo")
    refresh = st.checkbox("Download a fresh copy if it's already here")
    fetch_clicked = st.button("Fetch and inspect", type="primary", width="stretch", disabled=not url.strip())
    st.caption("Node.js projects only. Nothing from the repository is run on your machine.")

if fetch_clicked:
    with st.status(f"Fetching {url.strip()}", expanded=True) as status:
        dest = None
        try:
            dest = fetch(url, refresh, log=status.write)
        except FetchError as err:
            status.update(label="This repository can't be inspected", state="error", expanded=True)
            st.error(str(err))
        except Exception as err:
            status.update(label="Fetching stopped unexpectedly", state="error", expanded=True)
            st.error(f"{type(err).__name__}: {err}")
        if dest is not None:
            scan(dest, "HEAD", "auto", status)
            st.session_state["repo_choice"] = dest.name

repos = list_repos()
if not repos:
    st.markdown("# Nothing inspected yet")
    st.markdown("Paste a public GitHub link under **Add a repository from GitHub**, or run `setup.bat` to add OWASP Juice Shop.")
    st.stop()
names = [p.name for p in repos]
if st.session_state.get("repo_choice") not in names:
    st.session_state["repo_choice"] = "juice-shop" if "juice-shop" in names else names[0]
repo = TARGETS / st.sidebar.selectbox("Repository", names, key="repo_choice")
section = st.sidebar.radio("Go to", SECTIONS, key="section")

with st.sidebar.expander("Inspection settings"):
    commits = recent_commits(repo)
    base_label = st.selectbox("Compare changes against", [c[0] for c in commits], index=0,
                              help="The Changes section lists what changed in package.json, the lockfile, "
                                   "Dockerfiles and CI workflows since this commit.")
    base_ref = dict(commits)[base_label]
    scanner = st.selectbox("Vulnerability source", ["auto", "osv", "npm-audit"],
                           format_func={"auto": "OSV, falling back to npm audit", "osv": "OSV only",
                                        "npm-audit": "npm audit only"}.get)
if st.sidebar.button("Inspect again", width="stretch"):
    with st.status(f"Inspecting {repo.name}", expanded=True) as status:
        scan(repo, base_ref, scanner, status)

# ---------------- load results ----------------
out = out_dir_for(repo)
report = load(out, "evidence_report.json")
if not report:
    st.markdown(f"# {repo.name}")
    st.markdown("This repository hasn't been inspected yet. Choose **Inspect again** in the sidebar.")
    st.stop()

inventory, deps = load(out, "inventory.json"), load(out, "dependency_inventory.json")
vulns = load(out, "vulnerability_findings.json") or {"findings": [], "scanner": None, "total": 0}
susp = load(out, "suspicious_changes.json") or {"findings": [], "base_ref": "HEAD", "notes": []}
m, sev = report["metrics"], report["metrics"]["vulnerabilities_by_severity"]
vdf = pd.DataFrame(vulns["findings"])
ddf = pd.DataFrame(deps["dependencies"]) if deps else pd.DataFrame()
changes = [f for f in susp["findings"] if f["kind"] == "change"]
gpath = out / "dependency_graph.json"

# ---------------- manifest header (every section) ----------------
st.markdown(f'<div class="repo-kicker">Inspection manifest</div>', unsafe_allow_html=True)
st.markdown(f"# {repo.name}")
crit_high = f"{sev.get('critical', 0)} / {sev.get('high', 0)}"
st.markdown(f"""
<div class="manifest">
 <div><div class="k">Commit</div><div class="v"><span class="mono">{escape((report['commit'] or 'n/a')[:9])}</span></div></div>
 <div><div class="k">Inspected</div><div class="v"><small>{escape(when(report['generated_at']))}</small></div></div>
 <div><div class="k">Packages installed</div><div class="v">{m['npm_packages']} <small>{m['direct_dependencies']} chosen, {m['transitive_dependencies']} pulled in</small></div></div>
 <div><div class="k">Advisories</div><div class="v">{m['vulnerabilities']} <small>in {len({(v['package'], v['installed_version']) for v in vulns['findings']})} packages</small></div></div>
 <div><div class="k">Critical / high</div><div class="v {'red' if sev.get('critical') else ''}">{crit_high}</div></div>
 <div><div class="k">Changes since <span class="mono">{escape(str(susp['base_ref'])[:9])}</span></div><div class="v">{len(changes)}</div></div>
</div>""", unsafe_allow_html=True)
if report.get("errors"):
    st.error("Some agents failed during the last inspection: " + " | ".join(report["errors"]))


# ================= sections =================
def summary():
    score, letter, verdict, color, breakdown = risk_grade(vdf, changes, inventory)
    left, right = st.columns([5, 7], gap="large")
    with left:
        st.markdown(f"""<div class="stamp-wrap"><div class="stamp" style="--c:{color}">
            <div class="grade">{letter}</div>
            <div class="verdict">{escape(verdict)}<span>Score {score} of 100</span></div></div></div>""",
                    unsafe_allow_html=True)
        prod_n = int((vdf.scope == "prod").sum()) if not vdf.empty else 0
        fixed = int(vdf.fixed_version.notna().sum()) if not vdf.empty else 0
        sentence = (f"{repo.name} ships {m['npm_packages'] - inventory['summary']['dev']} packages to production. "
                    f"{prod_n} of the {m['vulnerabilities']} known advisories affect them"
                    + (f", and {fixed} have a fixed version available." if m["vulnerabilities"] else ".")
                    + (f" {len(changes)} supply-chain changes were found since the chosen baseline."
                       if changes else " Nothing in the manifests or pipelines changed since the chosen baseline."))
        st.markdown(f'<p class="verdict-text">{escape(sentence)}</p>', unsafe_allow_html=True)
        with st.expander("How this grade is calculated"):
            st.markdown("Start at 100 and subtract points for each real finding below. "
                        "A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, otherwise F.")
            if breakdown.empty:
                st.markdown("No deductions.")
            else:
                st.dataframe(breakdown, hide_index=True, width="stretch")
    with right:
        st.markdown("### Needs attention first")
        items = []
        for f in changes:
            if f["severity"] in ("critical", "high"):
                items.append((0, f["severity"], f"<b>{escape(f['title'])}</b> in <code>{escape(f['file'])}</span>. "
                                                f"{escape(f['why_suspicious'])}"))
        if not vdf.empty:
            grouped = vdf[vdf.severity.isin(["critical", "high"])].groupby(["package", "installed_version"])
            for (pkg, ver), grp in grouped:
                worst = "critical" if (grp.severity == "critical").any() else "high"
                row = grp.iloc[0]
                via = "a direct dependency" if row.direct else "pulled in by " + ", ".join(mono(v) for v in row.introduced_via[:2])
                fix = grp.fixed_version.dropna()
                fix_txt = f"Fixed in {fix.max()}." if len(fix) else "No fixed version published."
                scope = "" if row.scope == "prod" else " Dev-only, not shipped."
                items.append((1 if row.scope == "prod" else 3, worst,
                              f"{mono(pkg + '@' + ver)} has {len(grp)} "
                              f"{'advisory' if len(grp) == 1 else 'advisories'} ({escape(', '.join(grp.id[:2]))}"
                              f"{'…' if len(grp) > 2 else ''}). It is {via}. {escape(fix_txt)}{scope}"))
        items.sort(key=lambda x: (x[0], SEVERITIES.index(x[1])))
        if not items:
            st.markdown("Nothing critical or high. Review the Vulnerabilities and Changes sections for lower-severity items.")
        else:
            st.markdown('<ul class="attention">' + "".join(f"<li>{sev_badge(s)}<div>{t}</div></li>"
                                                         for _, s, t in items[:8]) + "</ul>",
                        unsafe_allow_html=True)
            if len(items) > 8:
                st.caption(f"{len(items) - 8} more in Vulnerabilities and Changes.")

    st.markdown("### Where the advisories come from")
    if vdf.empty:
        st.markdown("No known advisories.")
    else:
        a, b = st.columns([3, 2], gap="large")
        with a:
            counter = Counter(d for vias in vdf.introduced_via for d in set(vias))
            df = pd.DataFrame(counter.most_common(10), columns=["direct dependency", "advisories reached"])
            st.altair_chart(bar(df, "advisories reached", "direct dependency", "#D9622B", 300), width="stretch")
            st.caption("Each bar is a package listed in package.json, and how many advisories sit underneath it.")
        with b:
            rows = [{"severity": s, "advisories": sev[s]} for s in SEVERITIES if sev.get(s)]
            sdf = pd.DataFrame(rows)
            st.altair_chart(bar(sdf, "advisories", "severity", height=200, sort=[r["severity"] for r in rows],
                                color_enc=alt.Color("severity:N", legend=None, scale=alt.Scale(
                                    domain=list(SEV_COLOR), range=list(SEV_COLOR.values())))), width="stretch")
            t = report.get("trace")
            if t:
                st.markdown(f"Deepest-reaching example: {mono(t['package'])} arrives via "
                            + " → ".join(mono(x) for x in t["shortest_path"]) + ".",
                            unsafe_allow_html=True)


def packages():
    section_title("Packages", "Every package resolved from package-lock.json. Look one up to see why it's installed, "
                              "its licence, and any advisories.")
    if ddf.empty:
        st.markdown("No package inventory in the last inspection.")
        return
    names = sorted(ddf.name.unique())
    vulnerable_names = set(vdf.package) if not vdf.empty else set()
    default = names.index(report["trace"]["package"].rsplit("@", 1)[0]) if report.get("trace") and \
        report["trace"]["package"].rsplit("@", 1)[0] in names else 0
    pick = st.selectbox("Look up a package", names, index=default,
                        format_func=lambda n: n + ("  (has advisories)" if n in vulnerable_names else ""))
    rows = ddf[ddf.name == pick]
    g, nodes = load_graph(str(gpath), gpath.stat().st_mtime) if gpath.exists() else (None, {})
    st.markdown(f"### <code>{escape(pick)}</span>", unsafe_allow_html=True)
    facts = st.columns(4)
    facts[0].markdown(f"**Installed versions**  \n{', '.join(sorted(rows.version.unique()))}")
    facts[1].markdown(f"**Chosen directly?**  \n{'Yes, listed in package.json' if rows.type.eq('direct').any() else 'No, pulled in'}")
    facts[2].markdown(f"**Licence**  \n{', '.join(sorted(set(rows.license.fillna('not declared'))))}")
    facts[3].markdown(f"**Runs code on install?**  \n{'Yes (install script)' if rows.has_install_script.any() else 'No'}")
    for _, r in rows.iterrows():
        info = nodes.get(r.lock_path)
        if info:
            st.markdown(f"Version **{r.version}** ({r.scope}) arrives through: "
                        + " → ".join(f"`{x}`" for x in info["shortest_path"]))
    pv = vdf[vdf.package == pick] if not vdf.empty else vdf
    if not pv.empty:
        st.markdown(f"**Advisories ({len(pv)})**")
        st.dataframe(pv[["id", "severity", "installed_version", "fixed_version", "title"]], hide_index=True, width="stretch")

    st.markdown("### All packages")
    c1, c2, c3 = st.columns([2, 1, 1])
    q = c1.text_input("Filter by name", placeholder="e.g. express")
    kind = c2.selectbox("Chosen or pulled in", ["All", "Chosen directly", "Pulled in"])
    scope = c3.selectbox("Used in", ["All", "Production", "Development only"])
    view = ddf.copy()
    if q:
        view = view[view.name.str.contains(q, case=False, regex=False)]
    if kind != "All":
        view = view[view.type == ("direct" if kind == "Chosen directly" else "transitive")]
    if scope != "All":
        view = view[(view.scope == "dev") == (scope == "Development only")]
    st.dataframe(view[["name", "version", "type", "scope", "license", "declared_range", "has_install_script", "lock_path"]],
                 hide_index=True, width="stretch", height=360)
    st.caption(f"{len(view)} of {len(ddf)} packages shown.")

    st.markdown("### Same package, several versions")
    sprawl = ddf.groupby("name").version.nunique().sort_values(ascending=False)
    sprawl = sprawl[sprawl > 1]
    if sprawl.empty:
        st.markdown("Every package is installed in exactly one version.")
    else:
        st.markdown(f"{len(sprawl)} packages are installed in more than one version. Each extra copy is another "
                    "thing to patch.")
        sp = pd.DataFrame({"package": sprawl.index, "versions installed": sprawl.values,
                           "versions": [", ".join(sorted(ddf[ddf.name == n].version.unique())) for n in sprawl.index]})
        st.dataframe(sp.head(25), hide_index=True, width="stretch")


def dependency_map():
    section_title("Dependency map")
    if not gpath.exists():
        st.markdown("The dependency map wasn't produced in the last inspection.")
        return
    g, nodes = load_graph(str(gpath), gpath.stat().st_mtime)
    depth, size = graph_stats(str(gpath), gpath.stat().st_mtime)
    vulnerable = {f"{v['package']}@{v['installed_version']}" for v in vulns["findings"]}
    vuln_nodes = {n for n in g.nodes if g.nodes[n]["label"] in vulnerable}
    st.markdown(f"`{g.nodes['ROOT']['label']}` lists **{len(size)}** packages in package.json. Those need others, "
                f"which need others in turn: **{g.number_of_nodes() - 1 - len(size)}** more get installed without "
                f"anyone choosing them, up to **{max(depth.values())}** levels deep.")
    a, b = st.columns([3, 2], gap="large")
    with a:
        st.markdown("### Heaviest direct dependencies")
        leads = set().union(*(nx.ancestors(g, v) | {v} for v in vuln_nodes)) if vuln_nodes else set()
        big = pd.DataFrame([{"dependency": g.nodes[n]["label"], "packages brought in": c,
                             "status": "advisories underneath" if n in leads else "none known"}
                            for n, c in sorted(size.items(), key=lambda x: -x[1])[:12]])
        st.altair_chart(bar(big, "packages brought in", "dependency", height=380, color_enc=alt.Color(
            "status:N", scale=alt.Scale(domain=["advisories underneath", "none known"],
                                        range=["#D9622B", BLUE]), legend=alt.Legend(orient="bottom", title=None))),
            width="stretch")
    with b:
        st.markdown("### Packages at each depth")
        levels = Counter(v for n, v in depth.items() if n != "ROOT")
        lv = pd.DataFrame({"depth": [str(x) for x in sorted(levels)], "packages": [levels[x] for x in sorted(levels)]})
        st.altair_chart(alt.Chart(lv).mark_bar(color=STEEL, cornerRadiusEnd=2).encode(
            x=alt.X("depth:N", sort=None, title="depth (1 = listed in package.json)"),
            y=alt.Y("packages:Q", title=None), tooltip=["depth", "packages"]).properties(height=380), width="stretch")

    st.markdown("### Where the vulnerable packages sit")
    if not vuln_nodes:
        st.markdown("No package in this tree has known advisories.")
    else:
        routes = st.radio("Routes shown per vulnerable package", [1, 2, 3], horizontal=True, key="routes")
        st.markdown('<div style="max-width:980px;margin:0 auto">' + vuln_graph.radial_svg(g, vuln_nodes, per_node=routes)
                    + "</div>", unsafe_allow_html=True)
        legend = "".join(f'<span class="swatch" style="background:{c}"></span>{escape(n)}' for n, c in vuln_graph.LEGEND)
        st.markdown(f'<p class="note">{legend}<span class="swatch" style="background:#D9622B"></span>path to a vulnerable package. '
                    f'Small dots are direct dependencies with no known advisories underneath. Hover any dot for its name.</p>',
                    unsafe_allow_html=True)
        svg = out / "vulnerability_graph.svg"
        if svg.exists():
            st.download_button("Download this graph (SVG)", svg.read_bytes(), svg.name, "image/svg+xml")

    st.markdown("### Trace a package back to package.json")
    only = st.toggle("Only packages with advisories", value=bool(vuln_nodes))
    pool = sorted(vuln_nodes if (only and vuln_nodes) else set(g.nodes) - {"ROOT"}, key=lambda n: g.nodes[n]["label"])
    trace_pkg = report["trace"]["package"] if report.get("trace") else None
    default = next((i for i, n in enumerate(pool) if g.nodes[n]["label"] == trace_pkg), 0)
    target = st.selectbox("Package", pool, index=default, format_func=lambda n: g.nodes[n]["label"])
    info, sp = nodes[target], nodes[target]["shortest_path"]
    if g.nodes[target].get("direct"):
        st.markdown(f"`{info['label']}` is listed in package.json, so someone chose it.")
    else:
        st.markdown(f"Nobody chose `{info['label']}`. It arrives through `{sp[1] if len(sp) > 1 else '?'}`, "
                    f"{len(sp) - 1} levels down. Direct dependencies that lead to it: "
                    + ", ".join(f"`{x}`" for x in info["introduced_via"]) + ".")
    ids = sorted({v["id"] for v in vulns["findings"] if f"{v['package']}@{v['installed_version']}" == info["label"]})
    if ids:
        st.markdown(f"Advisories on this version: {', '.join(ids)}")
    paths = sorted((p for _, p in zip(range(25), nx.all_simple_paths(g, "ROOT", target, cutoff=12))), key=len)[:3]
    st.graphviz_chart(paths_dot(g, paths, target, vulnerable))
    st.markdown(f'<p class="note">The {len(paths)} shortest route{"s" if len(paths) != 1 else ""} from the app. '
                f'<span class="swatch" style="background:{INK}"></span>app'
                f'<span class="swatch" style="background:{BLUE}"></span>in package.json'
                f'<span class="swatch" style="background:{STEEL}"></span>pulled in'
                f'<span class="swatch" style="background:#D9622B"></span>has advisories'
                f'<span class="swatch" style="background:{RED}"></span>selected</p>', unsafe_allow_html=True)

    st.markdown("### Browse the whole tree")
    full = out / "dependency_graph.html"
    if full.exists():
        show_html(full.read_text(encoding="utf-8"), 700)
        st.download_button("Download the tree browser (HTML)", full.read_bytes(), full.name, "text/html")


def vulnerabilities():
    src = {"npm-audit": "npm audit (GitHub Advisory Database)", "osv": "OSV-Scanner (osv.dev)"}.get(vulns.get("scanner"),
                                                                                                    vulns.get("scanner"))
    section_title("Vulnerabilities", f"Reported by {src}. Every row comes straight from the scanner's output, "
                                     f"saved in <code>{escape(str(out.relative_to(ROOT)))}/raw</span>.")
    if vdf.empty:
        st.markdown("No known advisories for the installed versions.")
        return
    df = vdf.copy()
    df["type"] = df.direct.map({True: "direct", False: "pulled in"})
    df["path"] = df.dependency_path.map(lambda p: " → ".join(p))
    df["aliases"] = df.aliases.map(lambda a: ", ".join(a))
    f1, f2, f3 = st.columns(3)
    sevs = [s for s in SEVERITIES if s in set(df.severity)]
    pick_sev = f1.multiselect("Severity", sevs, sevs)
    pick_scope = f2.selectbox("Used in", ["All", "Production", "Development only"])
    pick_fix = f3.selectbox("Fix", ["All", "Fixed version available", "No fix published"])
    view = df[df.severity.isin(pick_sev)]
    if pick_scope != "All":
        view = view[(view.scope != "prod") == (pick_scope == "Development only")]
    if pick_fix != "All":
        view = view[view.fixed_version.notna() == (pick_fix == "Fixed version available")]
    st.dataframe(view[["id", "aliases", "severity", "package", "installed_version", "fixed_version", "type",
                       "scope", "affected_range", "title", "path", "reference"]],
                 hide_index=True, width="stretch", height=420,
                 column_config={"reference": st.column_config.LinkColumn("source")})
    st.caption(f"{len(view)} of {len(df)} advisories shown. "
               + ("Fixed versions marked as derived come from the advisory's affected range."
                  if (df.fixed_version_source == "derived from advisory range upper bound").any() else ""))

    st.markdown("### Fix availability by direct dependency")
    rows = defaultdict(lambda: {"advisories": 0, "with a fix": 0, "packages": set(), "worst": "unknown"})
    for _, r in df.iterrows():
        for d in (r.introduced_via or [f"{r.package}@{r.installed_version}"]):
            e = rows[d]
            e["advisories"] += 1
            e["with a fix"] += int(pd.notna(r.fixed_version))
            e["packages"].add(f"{r.package}@{r.installed_version}")
            if SEVERITIES.index(r.severity) < SEVERITIES.index(e["worst"]):
                e["worst"] = r.severity
    table = pd.DataFrame([{"direct dependency": k, "worst severity": v["worst"], "advisories": v["advisories"],
                           "with a fixed version": v["with a fix"], "affected packages": ", ".join(sorted(v["packages"]))}
                          for k, v in rows.items()]).sort_values(["advisories"], ascending=False)
    st.dataframe(table, hide_index=True, width="stretch")
    st.download_button("Download advisories (JSON)", (out / "vulnerability_findings.json").read_bytes(),
                       "vulnerability_findings.json", "application/json")

    recs = load(out, "fix_recommendations.json") or []
    st.markdown("### How to fix each package")
    st.markdown('<p class="note">Built from the scanner data: each advisory\'s fixed version and, with npm audit, its '
                'own suggestion of which package to change. Nothing is changed automatically.</p>', unsafe_allow_html=True)
    if recs:
        st.dataframe(pd.DataFrame([{"priority": r["priority"], "package": f"{r['package']}@{r['installed_version']}",
                                    "worst": r["worst_severity"], "advisories": r["advisories"], "used in": r["scope"],
                                    "how it got in": "direct" if r["direct"] else ", ".join(r["introduced_via"][:2]),
                                    "what to do": r["action"], "fixed in": r["fixed_in"] or "no fix"} for r in recs]),
                     hide_index=True, width="stretch")
        for r in recs:
            with st.expander(f"{r['priority'][:2]}  {r['package']}@{r['installed_version']}: {r['action']}"):
                for step in r["steps"]:
                    st.markdown(f"- {step}")
                st.markdown(f'<p class="note">Advisories: {escape(", ".join(r["ids"]))}</p>', unsafe_allow_html=True)
        csv = out / "fix_recommendations.csv"
        if csv.exists():
            st.download_button("Download recommendations (CSV)", csv.read_bytes(), csv.name, "text/csv")


def changes_section():
    section_title("Changes", f"What changed in package.json, the lockfile, Dockerfiles and CI workflows since "
                             f"<code>{escape(str(susp['base_ref']))}</span>. Scripts are read, never run. "
                             "Pick an older commit under Inspection settings to look further back.")
    for note in susp.get("notes", []):
        st.markdown(f'<p class="note">{escape(note)}</p>', unsafe_allow_html=True)
    if not changes:
        st.markdown("No supply-chain changes since this baseline.")
    for f in changes:
        with st.expander(f"{f['severity'].title()}: {f['title']}"):
            st.markdown(f"`{f['file']}`  \n{f['why_suspicious']}")
            if f["before"] is not None or f["after"] is not None:
                l, r = st.columns(2)
                l.markdown("Before")
                l.code(f["before"] or "(not present)", wrap_lines=True)
                r.markdown("After")
                r.code(f["after"] or "(not present)", wrap_lines=True)
            if f["evidence"]:
                st.json(f["evidence"], expanded=False)
    posture = [f for f in susp["findings"] if f["kind"] == "baseline"]
    st.markdown("### Standing observations")
    st.markdown('<p class="note">Things true of the current code regardless of the baseline.</p>', unsafe_allow_html=True)
    for f in posture:
        with st.expander(f"{f['severity'].title()}: {f['title']}"):
            st.markdown(f"`{f['file']}`  \n{f['why_suspicious']}")
            if f["evidence"]:
                st.json(f["evidence"], expanded=False)


LICENCE_GROUPS = [
    ("Strong copyleft", ("AGPL", "GPL", "CC-BY-SA", "EUPL", "SSPL", "OSL")),
    ("Weak copyleft", ("LGPL", "MPL", "EPL", "CDDL", "CPL")),
    ("Permissive", ("MIT", "ISC", "APACHE", "BSD", "0BSD", "BLUEOAK", "UNLICENSE", "CC0", "PYTHON", "ZLIB",
                    "WTFPL", "ARTISTIC", "CC-BY", "OFL", "BOOST", "X11")),
]


def licence_group(lic) -> str:
    if lic is None or pd.isna(lic) or not str(lic).strip() or str(lic).upper() in ("NONE", "UNLICENSED") or "SEE LICENSE" in str(lic).upper():
        return "Not declared"
    u = str(lic).upper()
    for name, keys in LICENCE_GROUPS:
        if any(u.startswith(k) or f"({k}" in u or f" {k}" in u for k in keys):
            return name
    return "Other"


def licences():
    section_title("Licences", "Read from each package's entry in package-lock.json.")
    if ddf.empty:
        return
    df = ddf.copy()
    df["licence"] = df.license.fillna("not declared")
    df["group"] = df.license.map(licence_group)
    counts = df.group.value_counts()
    order = ["Permissive", "Weak copyleft", "Strong copyleft", "Other", "Not declared"]
    colors = [GREEN, AMBER, RED, STEEL, "#9AA7B3"]
    a, b = st.columns([2, 3], gap="large")
    with a:
        gdf = pd.DataFrame({"group": [o for o in order if o in counts], "packages": [int(counts[o]) for o in order if o in counts]})
        st.altair_chart(bar(gdf, "packages", "group", height=220, sort=list(gdf.group), color_enc=alt.Color(
            "group:N", legend=None, scale=alt.Scale(domain=order, range=colors))), width="stretch")
        flagged = df[df.group.isin(["Strong copyleft", "Weak copyleft", "Not declared", "Other"])]
        prod_flagged = flagged[flagged.scope != "dev"]
        st.markdown(f"{len(prod_flagged)} shipped packages use a copyleft, unusual or undeclared licence. "
                    "Those are the ones a legal review would look at.")
    with b:
        top = df.licence.value_counts().head(12)
        st.altair_chart(bar(pd.DataFrame({"licence": top.index, "packages": top.values}), "packages", "licence",
                            STEEL, 300), width="stretch")
    st.markdown("### Packages to review")
    view = df[df.group != "Permissive"][["name", "version", "licence", "group", "scope", "type"]]
    st.dataframe(view.sort_values(["group", "name"]), hide_index=True, width="stretch")


def sbom():
    sb = report.get("sbom")
    section_title("SBOM", "Software bill of materials: the formal list of what ships, in a standard format other tools can read.")
    if not sb:
        st.markdown("No SBOM in the last inspection.")
        return
    st.markdown(f"**{sb['format']} {sb['spec_version']}**, generated by **{sb['tool']}**, with "
                f"{sb['component_count']} components. {sb['matched_inventory']} of its {sb['npm_component_count']} "
                f"npm components match the lockfile exactly. {sb['note']}")
    path = Path(sb["path"])
    if path.exists():
        bom = json.loads(path.read_text(encoding="utf-8"))
        st.download_button("Download SBOM (CycloneDX JSON)", path.read_bytes(), path.name, "application/json")
        st.dataframe(pd.DataFrame([{"name": (x.get("group", "") + "/" if x.get("group") else "") + x["name"],
                                    "version": x.get("version"), "type": x.get("type"), "purl": x.get("purl")}
                                   for x in bom.get("components", [])]), hide_index=True, width="stretch", height=480)


def agent_run():
    section_title("Agent run", "The LangGraph workflow from the last inspection. Each agent hands structured results to the next.")
    st.graphviz_chart(pipeline_dot(report["agent_log"]))
    st.dataframe(pd.DataFrame(report["agent_log"]), hide_index=True, width="stretch")
    for note in report.get("scanner_notes", []):
        st.markdown(f'<p class="note">Scanner fallback: {escape(note[:300])}</p>', unsafe_allow_html=True)
    hist = out / "history.jsonl"
    if hist.exists():
        rows = [json.loads(l) for l in hist.read_text(encoding="utf-8").splitlines() if l.strip()]
        st.markdown(f"### Inspection history ({len(rows)})")
        h = pd.DataFrame([{"inspected": when(r["at"]), "commit": (r.get("commit") or "")[:9], "baseline": r.get("base_ref"),
                           "packages": r["npm_packages"], "advisories": r["vulnerabilities"],
                           "critical": r["by_severity"].get("critical", 0), "high": r["by_severity"].get("high", 0),
                           "changes": r["suspicious_changes"]} for r in rows][::-1])
        st.dataframe(h, hide_index=True, width="stretch")
        if len(rows) > 1:
            t = pd.DataFrame([{"run": i + 1, "advisories": r["vulnerabilities"], "packages": r["npm_packages"]}
                              for i, r in enumerate(rows)])
            st.altair_chart(alt.Chart(t).mark_line(point=True, color=BLUE).encode(
                x=alt.X("run:O", title="inspection"), y=alt.Y("advisories:Q", title="advisories"),
                tooltip=["run", "advisories", "packages"]).properties(height=200), width="stretch")


def all_repositories():
    section_title("All repositories", "Every repository inspected on this machine. Pick one in the sidebar to open it.")
    rows = []
    for p in repos:
        r = load(out_dir_for(p), "evidence_report.json")
        if not r:
            rows.append({"repository": p.name, "inspected": "not yet"})
            continue
        mm, sv = r["metrics"], r["metrics"]["vulnerabilities_by_severity"]
        rows.append({"repository": p.name, "inspected": when(r["generated_at"]), "packages": mm["npm_packages"],
                     "chosen": mm["direct_dependencies"], "pulled in": mm["transitive_dependencies"],
                     "advisories": mm["vulnerabilities"], "critical": sv.get("critical", 0), "high": sv.get("high", 0),
                     "changes": mm["suspicious_changes"]})
    table = pd.DataFrame(rows)
    st.dataframe(table, hide_index=True, width="stretch")
    if "advisories" in table and table.advisories.notna().any():
        scanned = table.dropna(subset=["advisories"])
        long = scanned.melt(id_vars="repository", value_vars=["critical", "high"], var_name="severity",
                            value_name="count")
        long["count"] = long["count"].astype(int)
        st.altair_chart(bar(long, "count", "repository", height=60 + 46 * len(scanned), color_enc=alt.Color(
            "severity:N", scale=alt.Scale(domain=["critical", "high"], range=[RED, "#D9622B"]),
            legend=alt.Legend(orient="bottom", title=None))).properties(height=alt.Step(42)), width="stretch")
        st.caption("Critical and high advisories per repository.")


def report_section():
    section_title("Report", f"Written by {report['interpretation']['source']}.")
    st.markdown(report["interpretation"]["text"])
    st.markdown("### Downloads")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for f in sorted(out.rglob("*")):
            if f.is_file() and (f.parent == out or f.parent.name == "raw"):
                z.write(f, f.relative_to(out))
    c = st.columns(3)
    c[0].download_button("All results (ZIP)", buf.getvalue(), f"{repo.name}-guardian.zip", "application/zip",
                         width="stretch")
    md = out / "evidence_report.md"
    if md.exists():
        c[1].download_button("Report (Markdown)", md.read_bytes(), md.name, "text/markdown", width="stretch")
    c[2].download_button("Report (JSON)", (out / "evidence_report.json").read_bytes(), "evidence_report.json",
                         "application/json", width="stretch")


render = {"Summary": summary, "Packages": packages, "Dependency map": dependency_map, "Vulnerabilities": vulnerabilities,
 "Changes": changes_section, "Licences": licences, "SBOM": sbom, "Agent run": agent_run,
 "All repositories": all_repositories, "Report": report_section}[section]
render()
