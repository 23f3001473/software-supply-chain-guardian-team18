# Supply Chain Guardian — Evidence Report
Repo: `C:\Users\rohit\Downloads\software-supply-chain-guardian-day2\software-supply-chain-guardian\sandbox\supply-chain-risk-scanner\20261124-113104-baseline`  Commit: `9ee92d0e5cfc6736069857708e76279f7f46d55e`
Generated: 2026-11-24T06:02:27.084096+00:00

## Interpretation
_Source: deterministic template (no ANTHROPIC_API_KEY set)_

**Scope:** 236 npm packages (11 direct, 225 transitive) from package-lock.json.
**Vulnerabilities (osv):** 38 findings — critical: 3, high: 19, moderate: 13, low: 3. 1 affect production (shipped) packages.
**Highest-priority shipped findings:**
- GHSA-mrhx-c7xc-m3w5 in zod@3.25.76 (high, direct); fix: 4.6.6
**Trace:** tinypool@1.1.1 (GHSA-5gmw-xhrv-c9v3) reaches the app through supply-chain-risk-scanner@0.1.0 → vitest@3.2.4 → tinypool@1.1.1.
**Anomalies:** none relative to the base ref.

## Metrics
- total_components: 240
- npm_packages: 236
- direct_dependencies: 11
- transitive_dependencies: 225
- sbom_components: 6
- graph_nodes: 237
- graph_edges: 335
- vulnerabilities: 38
- vulnerabilities_by_severity: {'critical': 3, 'high': 19, 'moderate': 13, 'low': 3}
- vulnerable_prod: 1
- suspicious_changes: 0
- baseline_observations: 5

## Traced transitive vulnerability
- GHSA-5gmw-xhrv-c9v3 in tinypool@1.1.1
- Path: supply-chain-risk-scanner@0.1.0 → vitest@3.2.4 → tinypool@1.1.1

## Agent log
- 1. Repository Discovery Agent: ok — 6 manifests, 236 npm packages (11 direct), 4 container/CI components
- 2. SBOM Agent: ok — CycloneDX 1.6 via syft: 6 components
- 3. Dependency Analysis Agent: ok — 237 nodes, 335 edges
- 4. Vulnerability Detection Agent: ok — 38 findings via osv
- 5. Anomaly Detection Agent: ok — 0 anomalies vs 9ee92d0e5cfc6736069857708e76279f7f46d55e, 5 baseline observations