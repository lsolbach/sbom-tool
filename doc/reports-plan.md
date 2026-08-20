# Plan: Practical License & Vulnerability Reports

**Status:** Phases 1-5 and 7 implemented (domain, repository, policy adapter, reports, CLI
wiring, `--fail-on-violations` CI gate). Phase 6 is partially done: markdown output is
implemented as a hand-rolled adapter (`adapter/markdown/report.clj`) registered against the
`template/render` port, wired up via `-o/--output-format`; CSV output is still deferred, as is
any move to a template-engine-based renderer (e.g. comb, as in Overarch) -- the port is
designed so that swap can happen later without touching `application/report.clj` or the CLI.

## 1. Current state

**License side (done):**
- `domain/license.clj` — license extraction, SPDX expression parsing (AND/OR), policy-based
  `:white`/`:black`/`:grey` classification, multi-license-choice detection.
- `application/report.clj` — `licenses`, `multi-licensed`, `unidentified-licenses`.
- `adapter/policy/file_repository.clj` — reads `license-policy.edn` (whitelist/blacklist per
  component-type), falls back to bundled `resources/policy/license-policy.edn`.
- CLI only ever prints `report/licenses` as raw EDN (`adapter/ui/cli.clj:84`).

**Vulnerability side (gap):**
- `domain/sbom.clj` already specs `::vulnerability`/`::vulnerabilities` (id, source, severity,
  description, references, affected, properties).
- `adapter/cdx/file_repository.clj` already maps CycloneDX `vulnerabilities` into that shape
  (`map-vulnerability`, `map-severity`, `map-vulnerability-source`, `map-affected`).
- SPDX 2.2 has no native vulnerability concept, so `adapter/spdx/file_repository.clj` produces
  none — expected, not a bug.
- Nothing downstream exists: no `domain/vulnerability.clj`, no repository accessor, no report
  function, no policy (severity gating / accepted-risk), no CLI option.
- `application/template.clj` is an empty stub; `project.clj` already depends on
  `org.clojure/data.csv`, which is currently unused — signals that non-EDN output was intended.
- There is no `test/` directory yet despite `AGENTS.md` referencing one.

## 2. Goal

Add vulnerability reporting symmetric to the existing license reporting, and round out both
into something a CI pipeline can actually gate on (not just print EDN to stdout).

Reports to deliver:

| Report | Status |
|---|---|
| Licenses per component (with policy status) | exists |
| Multi-licensed components | exists |
| Unidentified licenses | exists |
| License summary (counts per status) | **new** |
| Blacklisted-license violations (CI-gateable) | **new** |
| Vulnerabilities per component | **new** |
| Vulnerability summary (counts per severity) | **new** |
| Policy-blocked vulnerabilities (CI-gateable) | **new** |

## 3. Design

### 3.1 Domain — `domain/vulnerability.clj` (new namespace, mirrors `domain/license.clj`)

- `severity-rank` — `{:unknown 0 :low 1 :medium 2 :high 3 :critical 4}`, for sorting/thresholds.
- `component-vulnerabilities [sbom component]` — vulnerabilities in `sbom`'s `::vulnerabilities`
  whose `::affected` contains the component's id. (Must be scoped to the *owning* sbom — see
  3.2 — since `affected` ids are only unique within one BOM document.)
- `highest-severity [vulnerabilities]`.
- `vulnerability-status [policy vulnerability]` → `:blocked` (severity ≥ policy `:max-severity`
  and id not in `:ignored`), `:accepted` (in `:ignored`), or `:ok`.
- `component-report [policy sbom component]` → id/name/version/type + per-vulnerability
  id/severity/status/description/source, analogous to `license/component-report`.

### 3.2 Repository — `application/repository.clj`

- Current `components` flattens every SBOM's components into one global `set` — fine for
  license reporting (license data lives *inside* the component), but unsafe for vulnerabilities
  because `::affected` ids are only meaningful within their own document.
- Add `sbom-components []` → seq of `[sbom component]` pairs (one per SBOM, not deduplicated
  across SBOMs) for any report that needs to join a component back to its own SBOM's
  vulnerabilities.
- Add `vulnerabilities []` → distinct vulnerabilities across all SBOMs (dedup by `::id`), for
  summary counts.
- Add `vulnerability-policies` accessor + `read-vulnerability-policies` multimethod, parallel to
  the existing `policies`/`read-policies`.

### 3.3 Policy — new file, same adapter pattern as license policy

- `resources/policy/vulnerability-policy.edn` (bundled default) + `example-vulnerability-policy.edn`
  at repo root:
  ```clojure
  {:max-severity :high   ;; :critical and :high vulnerabilities fail the gate
   :ignored #{}}         ;; accepted-risk vulnerability ids, exempted from failing
  ```
- `adapter/policy/file_repository.clj` gets a second `defmethod repo/read-vulnerability-policies`
  reading this file, same fallback-to-bundled-default behavior as `read-policy-file`.
- Kept as its own file/CLI flag rather than nesting under `license-policy.edn`, so the two
  policies stay independently swappable and backward compatible.

### 3.4 Reports — `application/report.clj`

- `license-summary []` — counts of licenses per `:white`/`:black`/`:grey` status.
- `blacklisted-licenses []` — `licenses` filtered to components with ≥1 `:black` license; the
  CI-gate-friendly view.
- `vulnerabilities-by-component []` — for each `[sbom component]` pair with ≥1 vulnerability,
  its id/name/version/type + vulnerabilities sorted by severity descending.
- `vulnerability-summary []` — counts of distinct vulnerabilities per severity, plus count of
  distinct affected components.
- `blocked-vulnerabilities []` — vulnerabilities whose `vulnerability/vulnerability-status` is
  `:blocked` under the configured policy; the CI-gate-friendly view.

### 3.5 Output — `application/template.clj`

Currently an empty stub, but `data.csv` is already a declared (unused) dependency, which
suggests it was meant for exactly this. Add a small `render` multimethod dispatching on an
output-format keyword:
- `:edn` (current behavior — pass-through `pr-str`/println).
- `:csv` (via `clojure.data.csv`, flattening whichever report map/vector is passed).
- `:markdown` (simple table renderer, good for pasting into a PR/CI summary).

### 3.6 CLI — `adapter/ui/cli.clj`

- New options:
  - `-r/--report REPORT` (default `:licenses`), one of `licenses`, `license-summary`,
    `multi-licensed`, `unidentified-licenses`, `blacklisted-licenses`, `vulnerabilities`,
    `vulnerability-summary`, `blocked-vulnerabilities`, `all`.
  - `-V/--vulnerability-policy PATH`, mirroring `-l/--license-policy`.
  - `-o/--output-format FORMAT` (`edn`|`csv`|`markdown`, default `edn`).
  - `-f/--fail-on-violations` — if set, exit `1` when `blacklisted-licenses` or
    `blocked-vulnerabilities` is non-empty. This is what makes the tool usable as a CI gate
    rather than just a printer.
- `initialize-state` also calls `repo/read-vulnerability-policies`.
- Replace the hardcoded `(println (report/licenses))` in `dispatch` with a lookup table from
  `:report` keyword to report fn, rendered via `template/render`, then compute the exit code.

### 3.7 Tests (new `test/` tree)

- `domain/vulnerability_test.clj` — severity ranking, policy status, component scoping.
- `domain/license_test.clj` (currently missing too) — expression parsing edge cases already
  documented in docstrings deserve regression tests.
- `application/report_test.clj` — small synthetic SBOM fixtures (reuse the shape already
  exercised in `cli.clj`'s `comment` blocks) covering all new report functions.
- Optional: one fixture `*.cdx.json` under `test/resources/sboms/` with a couple of
  vulnerabilities, exercised end-to-end through `repo/read-sboms` → `report/*`.

## 4. Rollout phases

1. **Domain**: `domain/vulnerability.clj` + tests. No wiring, no behavior change.
2. **Repository**: `sbom-components`, `vulnerabilities`, vulnerability-policy accessors.
3. **Policy adapter**: `vulnerability-policy.edn` default + file-repository multimethod.
4. **Reports**: all five new `report/*` functions, tested directly (bypassing CLI).
5. **CLI wiring**: `--report` selector + `--vulnerability-policy`; default behavior
   (`licenses`, EDN output) stays unchanged for existing callers/scripts.
6. **Output formatting**: `template.clj` CSV/Markdown renderers + `--output-format`.
7. **CI gate**: `--fail-on-violations` + exit code plumbing.
8. **Out of scope for now** (flag if useful later): OpenVEX/VEX ingestion so SPDX-based SBOMs
   can carry vulnerability data too; per-component-type vulnerability policy buckets (like the
   license policy's `:default`/`:library` split).

## 5. Open decisions

- Default `:max-severity` for the bundled vulnerability policy — proposing `:high` (blocks
  `:high` and `:critical`, leaves `:medium`/`:low`/`:unknown` as informational).
- Should the `:ignored` accepted-risk exemption support metadata (justification, expiry date)
  rather than a bare id set? Mirrors a similar question for license policy (currently no
  exemption mechanism for blacklisted licenses at all).
- Is CSV/Markdown output actually needed now, or is EDN sufficient for current usage (e.g.
  piped into another tool)? Affects whether phase 6 is worth doing immediately.
- Should `--report all` emit one combined map (all report keys at once) for a single CI
  artifact, in addition to selecting an individual report?
