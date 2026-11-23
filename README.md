# Software Supply Chain Guardian — Day 1: The Guardian's Eyes

> Know what you build. Trust what you ship.

Five LangGraph agents scan **OWASP Juice Shop**. Together they produce an inventory, a CycloneDX SBOM, a dependency graph, real vulnerability findings and anomaly findings. A Streamlit dashboard presents the results.
Facts come from tools (lockfile parser, Syft, OSV-Scanner / npm audit, git diff). The LLM (optional) only explains them.

## Architecture

```
START → 1. Repository Discovery → 2. SBOM → 3. Dependency Analysis → 4. Vulnerability Detection → 5. Anomaly Detection → report → END
```

| # | Agent | Tool / source of truth | Output |
|---|---|---|---|
| 1 | Repository Discovery | `package-lock.json`, `package.json`, Dockerfiles, compose, workflows | `inventory.json`, `dependency_inventory.json` |
| 2 | SBOM | Syft (fallback: `@cyclonedx/cyclonedx-npm`) | `juice-shop-sbom.json` (CycloneDX 1.6) |
| 3 | Dependency Analysis | lockfile + Node resolution rules, NetworkX, tree explorer | `dependency_graph.json`, `dependency_graph.html` |
| 4 | Vulnerability Detection | OSV-Scanner (fallback: `npm audit` → GitHub Advisory DB) | `vulnerability_findings.json`, `raw/` |
| 5 | Anomaly Detection | `git show <base>:file` vs working tree, static inspection | `suspicious_changes.json` |

The final `report` step is part of the workflow, not an agent. It combines the agents' structured results into `evidence_report.json/.md`. Agents pass Pydantic models (`guardian/models.py`) through the LangGraph state. If an LLM key is set and its text mentions a CVE/GHSA ID or `pkg@version` that isn't in the evidence, the text is rejected (`guardian/llm.py`).

## Setup on Windows (CMD)

Install Python 3.10+ (tick "Add to PATH"), Node.js 22+ and Git for Windows. Then:

```cmd
cd C:\ssg\software-supply-chain-guardian
setup.bat
run.bat
```

`setup.bat` handles the whole setup:
- creates `.venv` and installs the Python requirements
- downloads `syft.exe` and `osv-scanner.exe` into `tools\`
- enables git long paths
- clones Juice Shop and generates its lockfile with `npm install --package-lock-only --ignore-scripts`, which runs no install scripts

`run.bat` scans Juice Shop, runs the tests, then starts the dashboard at http://localhost:8501.

## Scan any public GitHub repo

**Dashboard:** paste a link such as `https://github.com/expressjs/express` into **Scan a GitHub repository**, then click **Fetch & scan**. You'll see each agent finish live, and the repo is added to the list and to the **All repositories** comparison.

**CMD:** `python -m guardian.cli --github https://github.com/expressjs/express` (add `--refresh` to re-clone).

Here's what happens:
1. The URL is validated: `github.com/owner/repo` only.
2. The repo is cloned into `target\` with its last 200 commits and long paths enabled.
3. If there's no `package-lock.json`, it's generated with `npm --package-lock-only --ignore-scripts`. **No code from the repo is executed.**
4. The 5 agents run, and results go to `reports\<repo>\`.
5. Non-npm repos (Python, Java, Go…), private or missing repos, and npm resolution failures get a clear message. Rejected clones are deleted.

Limits: public repos only, with `package.json` at the repo root (monorepos aren't supported yet).

## Setup on Linux / macOS

```bash
./setup.sh
```

## Run

```bash
python3 -m guardian.cli                                    # baseline Juice Shop → reports/
python3 -m guardian.cli --base-ref HEAD~49                 # anomalies in the last 49 real commits
python3 -m pytest                                          # 25 tests
streamlit run app.py                                       # dashboard on http://localhost:8501
```

Pick a scanner with `--scanner auto|osv|npm-audit`. `auto` tries OSV first and records why if it falls back.

## Fix recommendations and the vulnerability map

Every scan also writes:
- `fix_recommendations.json` / `.csv`: one entry per vulnerable package, with a priority (P1–P3), the action and exact steps. They come from npm audit's own `fixAvailable` data and each advisory's fixed version. Unsafe automatic fixes, such as npm suggesting a *downgrade* of the parent, are flagged, and an `overrides` pin is recommended instead. Nothing is applied automatically.
- `vulnerability_graph.svg`: a radial dependency graph. The project is in the centre, then a ring of direct dependencies, with indirect levels shaded outward. Vulnerable packages are red, and the orange paths show how each one gets in. It's drawn in pure Python, so Graphviz isn't needed.

## Dashboard (dark theme, follows the Day 1 brief)

| Page | What it shows |
|---|---|
| Overview | Inspection stamp (grade A–F, formula shown), the Day 1 checkpoint answered (what is in it, what changed, what appears risky), "fix these first", and a checklist of the five steps |
| 1 · Components | Package lookup (versions, why it's installed, licence, install scripts, remediation), filterable package list, manifests, licences, version sprawl |
| 2 · Supply chain view | CycloneDX SBOM, where components come from, radial vulnerability map, heaviest dependencies, depth, trace any package to its origin, container images and CI workflows inspected, full tree browser |
| 3 · Vulnerabilities | Severity counts, remediation package by package (priority, steps, advisories with CVE, CVSS and source links), all advisories with filters |
| 4 · Suspicious changes | The seven checks with counts (since baseline and in current code), each change with before/after, evidence and remediation, standing observations with remediation |
| 5 · Evidence & report | PDF download, summary, agent run, every evidence file with its SHA-256 hash, all downloads, inspection history |
| Compare repositories | Every inspected repo with its grade |

**Evidence report PDF:** a "Evidence report PDF" button sits on every page. The report is generated on every scan (`reports/evidence_report.pdf`) and contains:
- a cover page with the grade and checkpoint
- an executive summary and grade breakdown
- method, components and the supply chain view, with the vulnerability map
- every advisory, with CVSS, CWE and path
- the remediation plan
- suspicious changes and observations, with remediation
- licences
- an appendix of evidence files with their SHA-256 hashes

## Demo script (step by step)

1. **Summary.** The stamp (Juice Shop is deliberately insecure, so it gets an F) and the reasons behind it. Open "How this grade is calculated".
2. **Packages.** Look up `crypto-js`: why it's installed, its licence and its 2 advisories. Then scroll to "Same package, several versions".
3. **Dependency map.** Heaviest dependencies, then trace `crypto-js` back to `pdfkit`. In the tree browser, click **Show every route to an advisory**.
4. **Vulnerabilities.** Filter to production and "Fixed version available".
5. **Changes.** Under *Inspection settings*, pick an older commit (e.g. 49 commits back) and click **Inspect again** to see real changes.
6. **Licences.** The shipped packages with undeclared or copyleft licences.
7. **Add a repository from GitHub.** Paste `https://github.com/expressjs/express`, click **Fetch and inspect**, watch the agents run, then open **All repositories**.
8. **Report.** Download everything as a ZIP.

## Honesty notes

- Vulnerabilities come only from the scanner's raw output, saved in `reports/raw/`. A test checks that every reported ID appears there.
- In `npm audit` mode, IDs are GHSA (no CVE aliases). The fixed version is derived from the advisory's `<X` upper bound and labeled as derived. OSV mode adds CVE aliases and explicit fixed versions.
- Anomalies come only from real git history: `git show <baseline>:file` compared with the current files. No changes are injected, and scripts are only read, never run.
- The unit tests build small throwaway repos in a temp folder to check the detectors. These are never written to `reports/` and never appear in the dashboard.
- Day 2 (remediation, patches, PRs, deployment) is out of scope.
