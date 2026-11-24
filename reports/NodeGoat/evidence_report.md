# Supply Chain Guardian — Evidence Report
Repo: `C:\Users\rohit\Downloads\software-supply-chain-guardian-day2\software-supply-chain-guardian\target\NodeGoat`  Commit: `c5cb68a7084e4ae7dcc60e6a98768720a81841e8`
Generated: 2026-11-24T05:50:50.503840+00:00

## Interpretation
_Source: deterministic template (no ANTHROPIC_API_KEY set)_

**Scope:** 1479 npm packages (36 direct, 1443 transitive) from package-lock.json.
**Vulnerabilities (osv):** 311 findings — critical: 33, high: 169, moderate: 91, low: 17, unknown: 1. 61 affect production (shipped) packages.
**Highest-priority shipped findings:**
- GHSA-v8w9-2789-6hhr in bson@1.0.9 (critical, transitive via mongodb@2.2.36); fix: 1.1.4
- GHSA-xvch-5gv4-984h in minimist@0.0.10 (critical, transitive via forever@2.0.0, swig@1.4.2); fix: 1.2.6
- GHSA-xvch-5gv4-984h in minimist@0.0.8 (critical, transitive via cypress@3.3.1, forever@2.0.0); fix: 1.2.6
- GHSA-xvch-5gv4-984h in minimist@1.2.5 (critical, transitive via forever@2.0.0); fix: 1.2.6
- GHSA-fhjf-83wg-r2j9 in mixin-deep@1.3.1 (critical, transitive via forever@2.0.0, grunt-cli@1.3.2); fix: 1.3.2
**Trace:** set-value@0.4.3 (GHSA-4g88-fppr-53pp) reaches the app through owasp-nodejs-goat@1.3.0 → nodemon@1.19.1 → chokidar@2.1.6 → braces@2.3.2 → snapdragon@0.8.2 → base@0.11.2 → cache-base@1.0.1 → union-value@1.0.0 → set-value@0.4.3.
**Anomalies:** none relative to the base ref.

## Metrics
- total_components: 1488
- npm_packages: 1479
- direct_dependencies: 36
- transitive_dependencies: 1443
- sbom_components: 419
- graph_nodes: 1480
- graph_edges: 2295
- vulnerabilities: 311
- vulnerabilities_by_severity: {'critical': 33, 'high': 169, 'moderate': 91, 'low': 17, 'unknown': 1}
- vulnerable_prod: 61
- suspicious_changes: 0
- baseline_observations: 6

## Traced transitive vulnerability
- GHSA-4g88-fppr-53pp in set-value@0.4.3
- Path: owasp-nodejs-goat@1.3.0 → nodemon@1.19.1 → chokidar@2.1.6 → braces@2.3.2 → snapdragon@0.8.2 → base@0.11.2 → cache-base@1.0.1 → union-value@1.0.0 → set-value@0.4.3

## Agent log
- 1. Repository Discovery Agent: ok — 6 manifests, 1479 npm packages (36 direct), 9 container/CI components
- 2. SBOM Agent: ok — CycloneDX 1.6 via syft: 419 components
- 3. Dependency Analysis Agent: ok — 1480 nodes, 2295 edges
- 4. Vulnerability Detection Agent: ok — 311 findings via osv
- 5. Anomaly Detection Agent: ok — 0 anomalies vs HEAD, 6 baseline observations