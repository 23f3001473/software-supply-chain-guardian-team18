# Software Supply Chain Guardian

Five LangGraph agents scan **OWASP Juice Shop** and other npm repositories. Together they produce an inventory, a CycloneDX SBOM, a dependency graph, real vulnerability findings and anomaly findings. A React dashboard presents the results through a local Python API.
Facts come from tools (lockfile parser, Syft, OSV-Scanner / npm audit, git diff). The LLM only explains them.

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
- installs the React dashboard dependencies
- installs the TypeScript parser for offline dependency rules
- downloads `syft.exe` and `osv-scanner.exe` into `tools\`
- enables git long paths
- clones Juice Shop and generates its lockfile with `npm install --package-lock-only --ignore-scripts`, which runs no install scripts

`run.bat` builds React and starts the dashboard at http://127.0.0.1:8501. It opens the bundled Juice Shop report. Select **Inspect again** to refresh the report once the local clone is available.

## Scan any public GitHub repo

**Dashboard:** choose **Add repository**, paste a link such as `https://github.com/expressjs/express`, then click **Fetch and inspect**. The **Agent run** page shows each step as it finishes. The repository appears in the selector and under **All repositories**.

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
python3 -m pytest                                          # run the Python tests
npm --prefix frontend run build                            # build React
python3 app.py                                             # dashboard on http://127.0.0.1:8501
```

Every inspection reviews local dependency code with offline rules and looks up lockfile versions in OSV by default. If OSV is unavailable, `auto` tries npm audit and records the fallback. Use `--scanner osv` to use OSV for the advisory lookup without the npm audit fallback. The offline review still runs.

Open **Vulnerabilities** and use **Found by** to filter by **OSV**, **Offline rules**, or **npm audit** when used. Advisory rows include the published ID and any available fixed version. Offline matches include the rule, file and line, context, and suggested remediation. Check the coverage above the table to see how many dependencies had code available locally. Existing saved reports gain offline results after a new inspection.

The offline rules use installed dependencies and npm-cache tarballs that match the lockfile's integrity values. Set `GUARDIAN_NPM_CACHE` to use another cache directory containing `_cacache`. For an existing installation, run `npm ci --prefix guardian/source_scanner --ignore-scripts` once to install the local parser.

For frontend development, start `python app.py` in one terminal and run `npm --prefix frontend run dev` in another. Vite prints the development URL and proxies API requests to the Python server.

To browse checked-in reports before downloading scanner tools or cloning Juice Shop, install `requirements.txt`, run `npm --prefix frontend ci` and `npm --prefix frontend run build`, then start `python app.py`.

## Fix recommendations and the vulnerability map

Every scan also writes:
- `fix_recommendations.json` / `.csv`: one entry per vulnerable package, with a priority (P1–P3), the action and exact steps. They come from npm audit's own `fixAvailable` data and each advisory's fixed version. Unsafe automatic fixes, such as npm suggesting a *downgrade* of the parent, are flagged, and an `overrides` pin is recommended instead. Nothing is applied automatically.
- `vulnerability_graph.svg`: a radial dependency graph. The project is in the centre, then a ring of direct dependencies, with indirect levels shaded outward. Vulnerable packages are red, and the orange paths show how each one gets in. It's drawn in pure Python, so Graphviz isn't needed.

## Dashboard sections

| Section | What it shows (all from real scan output) |
|---|---|
| Summary | Inspection stamp (grade A–F, formula shown), "needs attention first" list, where advisories come from |
| Packages | Look up any package: versions, why it's installed, licence, install scripts, advisories. Full filterable list. Packages installed in several versions |
| Dependency map | Radial vulnerability map (project in the centre, red vulnerable packages, orange paths), heaviest direct dependencies, depth chart, trace any package, full tree browser |
| Vulnerabilities | Advisory and offline rule findings with source labels and coverage, advisory filters, and prioritised fix recommendations |
| Changes | What changed in manifests, lockfile, Dockerfiles and CI since a chosen real commit, plus standing observations |
| Licences | Licence mix from the lockfile; copyleft and undeclared licences to review |
| SBOM | CycloneDX file, match against the lockfile, download |
| Agent run | The 5-agent LangGraph run, plus inspection history over time |
| All repositories | Every inspected repository side by side |
| Report | Written summary; downloads (ZIP of everything, Markdown, JSON) |

The risk grade starts at 100 and subtracts points for real findings. Each deduction is listed under "How this grade is calculated", so the grade can always be explained.

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

- Published advisories come from scanner output in `reports/raw/`. Offline rule matches and coverage are saved in `dependency_review.json` in the inspection's report directory.
- In `npm audit` mode, IDs are GHSA (no CVE aliases). The fixed version is derived from the advisory's `<X` upper bound and labeled as derived. OSV mode adds CVE aliases and explicit fixed versions.
- Anomalies come only from real git history: `git show <baseline>:file` compared with the current files. No changes are injected, and scripts are only read, never run.
- The unit tests build small throwaway repos in a temp folder to check the detectors. These are never written to `reports/` and never appear in the dashboard.
- Day 2 (remediation, patches, PRs, deployment) is out of scope.
