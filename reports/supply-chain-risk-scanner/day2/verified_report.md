# Verified remediation report: supply-chain-risk-scanner

Generated 2026-11-24T06:03:35+00:00

## Outcome

- Risks: 21 prioritised, **0 verified as resolved**, 21 remaining (0 accepted)
- Advisories: None before → None after; grade None → None
- Risk points: 1015.5 → 1015.5
- Final confidence: **Low (0.5)** because nothing has been validated yet; 0 of 1 critical/high risks verified as resolved; audit trail hash chain intact

## Finding by finding

| Risk | Subject | Tier | Action | Decision | Status |
|---|---|---|---|---|---|
| RISK-001 | zod@3.25.76 | High (66.8) | Upgrade zod 3.25.76 → 4.6.6 | approve by Rohit | Approved, not validated yet |
| RISK-002 | vitest@3.2.4 | Medium (62.1) | Upgrade vitest 3.2.4 → 4.1.11 | - | Waiting for a human decision |
| RISK-003 | 2 container images are referenced by tag, not by digest | Medium (61.0) | Pin 2 container image(s) by digest | - | Waiting for a human decision |
| RISK-004 | tinypool@1.1.1 | Medium (56.7) | Pin tinypool to 2.1.2 with npm overrides | - | Waiting for a human decision |
| RISK-005 | vite@7.3.3 | Medium (55.5) | Pin vite to 8.3.3 with npm overrides | - | Waiting for a human decision |
| RISK-006 | js-yaml@4.1.1 | Medium (53.0) | Pin js-yaml to 4.3.2 with npm overrides | - | Waiting for a human decision |
| RISK-007 | source-map-js@1.2.1 | Medium (52.9) | Pin source-map-js to 1.2.2 with npm overrides | - | Waiting for a human decision |
| RISK-008 | 236 lockfile entries resolve outside registry.npmjs.org | Medium (52.0) | - | - | No action planned |
| RISK-009 | Where every package is downloaded from — non-registry sources found | Medium (52.0) | - | - | No action planned |
| RISK-010 | brace-expansion@1.1.15 | Medium (50.4) | Pin brace-expansion to 5.0.12 with npm overrides | - | Waiting for a human decision |
| RISK-011 | brace-expansion@5.0.6 | Medium (50.4) | Pin brace-expansion to 5.0.12 with npm overrides | - | Waiting for a human decision |
| RISK-012 | postcss@8.5.15 | Medium (49.1) | Pin postcss to 8.5.23 with npm overrides | - | Waiting for a human decision |
| RISK-013 | nanoid@3.3.12 | Medium (48.1) | Pin nanoid to 3.3.18 with npm overrides | - | Waiting for a human decision |
| RISK-014 | 2 CI actions not SHA-pinned | Medium (48.0) | Pin 2 CI action(s) to a commit SHA | - | Waiting for a human decision |
| RISK-015 | minimatch@10.2.5 | Low (44.8) | Pin minimatch to 11.0.1 with npm overrides | - | Waiting for a human decision |
| RISK-016 | @vitest/mocker@3.2.4 | Low (42.7) | Pin @vitest/mocker to 4.1.12 with npm overrides | - | Waiting for a human decision |
| RISK-017 | 2 of 3 production dependencies have no build provenance | Low (42.0) | - | - | No action planned |
| RISK-018 | esbuild@0.27.7 runs code when installed (download) | Low (42.0) | Security review: install script in esbuild@0.27.7 | - | Waiting for a human decision |
| RISK-019 | esbuild@0.28.0 runs code when installed (download) | Low (42.0) | Security review: install script in esbuild@0.28.0 | - | Waiting for a human decision |
| RISK-020 | esbuild@0.27.7 | Low (22.0) | Pin esbuild to 0.28.1 with npm overrides | - | Waiting for a human decision |
| RISK-021 | esbuild@0.28.0 | Low (22.0) | Pin esbuild to 0.28.1 with npm overrides | - | Waiting for a human decision |

## Audit trail

9 entries, chain intact.

## Responsible AI

- Agents 1-10 find, score and validate with deterministic tools; the LLM only explains evidence they produced.
- Every AI answer is grounding-checked: any advisory id or package@version not in the evidence gets the answer rejected.
- AI text is labelled as inference and shown next to, never mixed with, the verified evidence.
- No change is applied without a named human approval; nothing is merged, pushed or deployed automatically.
- Validation runs in a separate git worktree with dependency install scripts disabled.
- Only package names, versions, advisory text and public registry data are sent to the LLM; no secrets, tokens or source files.
- All prompts and responses are logged in day2/llm_log.jsonl; all decisions in a hash-chained audit log.
