# Supply Chain Guardian — Evidence Report
Repo: `C:\Users\rohit\Downloads\software-supply-chain-guardian-day2\software-supply-chain-guardian\target\juice-shop`  Commit: `c9f99228d9d56afb5f5ca7925376292f7fa44b13`
Generated: 2026-11-24T05:44:14.392477+00:00

## Interpretation
_Source: deterministic template (no ANTHROPIC_API_KEY set)_

**Scope:** 1249 npm packages (98 direct, 1151 transitive) from package-lock.json.
**Vulnerabilities (osv):** 54 findings — critical: 7, high: 20, moderate: 25, low: 2. 49 affect production (shipped) packages.
**Highest-priority shipped findings:**
- GHSA-rg76-677x-56q9 in crypto-js@3.3.0 (critical, transitive via pdfkit@0.11.0); fix: 4.0.0
- GHSA-xwcq-pm8m-c4vf in crypto-js@3.3.0 (critical, transitive via pdfkit@0.11.0); fix: 4.2.0
- GHSA-c7hr-j4mj-j2w6 in jsonwebtoken@0.1.0 (critical, transitive via express-jwt@0.1.3); fix: 4.2.2
- GHSA-c7hr-j4mj-j2w6 in jsonwebtoken@0.4.0 (critical, direct); fix: 4.2.2
- GHSA-jf85-cpcp-j695 in lodash@2.4.2 (critical, transitive via sanitize-html@1.4.2); fix: 4.17.12
**Trace:** crypto-js@3.3.0 (GHSA-rg76-677x-56q9) reaches the app through juice-shop@20.4.0-SNAPSHOT → pdfkit@0.11.0 → crypto-js@3.3.0.
**Anomalies:** none relative to the base ref.

## Metrics
- total_components: 1353
- npm_packages: 1249
- direct_dependencies: 98
- transitive_dependencies: 1151
- sbom_components: 584
- graph_nodes: 1250
- graph_edges: 2269
- vulnerabilities: 54
- vulnerabilities_by_severity: {'critical': 7, 'high': 20, 'moderate': 25, 'low': 2}
- vulnerable_prod: 49
- suspicious_changes: 0
- baseline_observations: 12

## Traced transitive vulnerability
- GHSA-rg76-677x-56q9 in crypto-js@3.3.0
- Path: juice-shop@20.4.0-SNAPSHOT → pdfkit@0.11.0 → crypto-js@3.3.0

## Agent log
- 1. Repository Discovery Agent: ok — 24 manifests, 1249 npm packages (98 direct), 104 container/CI components
- 2. SBOM Agent: ok — CycloneDX 1.6 via syft: 584 components
- 3. Dependency Analysis Agent: ok — 1250 nodes, 2269 edges
- 4. Vulnerability Detection Agent: ok — 54 findings via osv
- 5. Anomaly Detection Agent: ok — 0 anomalies vs HEAD, 12 baseline observations