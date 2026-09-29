# Plan: Extending the CVSS Domain Namespace to CVSS v4.0

**Status:** proposed
**Date:** 2026-09-29
**Related:** [dev/plans/cvss-v3-vector-parser.md](cvss-v3-vector-parser.md) (implemented; the
`sbom-tool.domain.cvss` namespace this plan extends with a third CVSS version), [dev/plans/cvss-v2-vector-parser.md](cvss-v2-vector-parser.md)
(proposed; the other CVSS version named in the same request, planned separately -- v2's Base Score
is a small, closed-form arithmetic extension, while this plan's v4 scoring algorithm is a
fundamentally larger and riskier reimplementation effort, detailed below), [dev/plans/osv-vulnerability-adapter.md](osv-vulnerability-adapter.md)
(implemented; OSV's `severity[]` schema already permits a `CVSS_V4`-typed entry, currently ignored
by `osv.clj`'s `record-severity`, the gap this plan closes).

## Problem

CVSS v4.0 (published November 2023 by FIRST) is the current CVSS version, and adoption is expected
to grow across the sources this tool already talks to: OSV's `severity[]` schema already permits a
`CVSS_V4`-typed entry alongside `CVSS_V3`/`CVSS_V2`, and NIST has committed to eventually scoring
new NVD CVEs under v4 as tooling matures. Today, `domain/cvss.clj` (per [dev/plans/cvss-v3-vector-parser.md](cvss-v3-vector-parser.md),
implemented) and `osv.clj`'s `record-severity` have no v4 tier at all -- a record whose only
severity signal is a CVSS v4 vector still reports `:unknown`. Unlike v2 (see the companion
[dev/plans/cvss-v2-vector-parser.md](cvss-v2-vector-parser.md)), v4's Base Score is **not** a
closed-form algebraic formula -- it is computed via a precomputed lookup table of "MacroVectors"
plus a distance-based interpolation step, making a from-scratch reimplementation a meaningfully
larger and more error-prone undertaking than either v2 or v3. This plan scopes exactly what full
v4 support requires, and is deliberately explicit about where the real implementation risk lives.

## Format research (done as part of this plan)

Verified against the official [CVSS v4.0 Specification Document](https://www.first.org/cvss/v4-0/specification-document)
and the [CVSS v4.0 reference calculator/implementation](https://github.com/FIRSTdotorg/cvss-calculator)
(FIRST's own JavaScript source, the authoritative implementation of the scoring algorithm below):

- **Vector string shape**: `CVSS:4.0/AV:<x>/AC:<x>/AT:<x>/PR:<x>/UI:<x>/VC:<x>/VI:<x>/VA:<x>/SC:<x>/
  SI:<x>/SA:<x>`, optionally followed by Threat, Environmental, or Supplemental metrics this plan
  does not parse (same Non-goal as v2/v3).
- **Base metrics are structurally different from v3**, not just renamed:
  - **Exploitability**: `AV` (Attack Vector: `N`/`A`/`L`/`P`), `AC` (Attack Complexity: `L`/`H`),
    `AT` (Attack Requirements: `N`/`P` -- **new in v4**, no v3 equivalent), `PR` (Privileges
    Required: `N`/`L`/`H`), `UI` (User Interaction: `N`/`P`/`A` -- v4 splits v3's binary `N`/`R`
    into `N`/Passive/Active).
  - **Vulnerable System Impact**: `VC`/`VI`/`VA` (`H`/`L`/`N`) -- impact to the system that has the
    vulnerability.
  - **Subsequent System Impact**: `SC`/`SI`/`SA` (`H`/`L`/`N`) -- impact to a *different* system the
    vulnerability lets an attacker reach.
  - **`Scope` is retired entirely** -- v3's single Scope-changed/unchanged flag is replaced by this
    Vulnerable-System-vs-Subsequent-System split, a genuine structural redesign, not a renaming.
- **No closed-form Base Score formula exists.** The v4 scoring algorithm (Specification, "Scoring"
  section) works by:
  1. Computing six **Equivalence Classes** (`EQ1`..`EQ6`), each a small integer (0, 1, or 2)
     derived from a documented combination of Base (and, if present, Threat/Environmental) metric
     values, per fixed classification rules the spec tabulates directly.
  2. Concatenating `EQ1..EQ6` into a six-digit **MacroVector** (e.g. `"122001"`) and looking up its
     nominal score in a **precomputed lookup table with one row per possible MacroVector
     combination** (270 rows in the reference implementation's own table) -- there is no algebraic
     shortcut that reproduces this table; it must be ported from source.
  3. Computing a handful of **"severity-decreased" neighbor MacroVectors** (each obtained by
     documented per-equivalence-class substitution rules, roughly "what would this MacroVector be
     if this one equivalence class were one notch less severe"), looking each up in the same table,
     and **linearly interpolating** the input vector's exact score within its own MacroVector's
     score band based on its metric-level distance from the "highest severity" reference vector
     that MacroVector's score represents.
  4. The final score is the MacroVector's nominal value minus a proportional adjustment from step 3,
     clamped to `[0.0, 10.0]` and rounded to one decimal place.
  This is a real reimplementation of a nontrivial, table-driven algorithm -- not a formula that can
  be safely re-derived from the specification's prose alone without risking a subtly wrong score.
- **Severity buckets are identical to v3's**, confirmed in the v4 Specification's own qualitative
  severity ratings table: None/Low/Medium/High/Critical at the same 0.1/4.0/7.0/9.0 thresholds
  already implemented by `domain.cvss/severity-of-score`. This is the one piece of good news in
  this plan's research -- v4 needs no separate `severity-of-score-v4` (unlike v2, whose three-bucket
  scale genuinely differs, see [dev/plans/cvss-v2-vector-parser.md](cvss-v2-vector-parser.md)); the
  existing v3 function is directly reusable once a v4 numeric score exists.
- **FIRST has revised the reference implementation's MacroVector table after initial publication**
  (documented corrections to specific macrovector edge cases in the calculator's changelog) --
  whatever version this plan's table is ultimately ported from must be recorded precisely (exact
  commit/release), so a future discrepancy against the live calculator can be triaged as "this port
  is stale" rather than "this port was always wrong."

## Goals

Given the scoring algorithm's genuine complexity (see Format research and Risks), this plan splits
into two independently landable tiers rather than one all-or-nothing implementation:

1. **`parse-vector-v4 [vector-string]`** (small, low-risk, useful on its own even before scoring
   exists) -- parses a `CVSS:4.0/...` Base vector into `{:av :ac :at :pr :ui :vc :vi :va :sc :si
   :sa}`, or nil if any of the eleven required Base metric keys is missing or carries an
   unrecognized value. Exactly analogous in shape and rigor to `parse-vector`/`parse-vector-v2`.
2. **`base-score-v4 [metrics]`** (the real effort) -- a full port of the MacroVector lookup table,
   the `EQ1..EQ6` classification rules, and the neighbor-interpolation algorithm from the official
   reference implementation, producing a numeric score in `[0.0, 10.0]`. The MacroVector table
   itself is bundled as a resource file (`resources/cvss/cvss-v4-macrovectors.edn`), not inlined as
   a source-code literal, mirroring this project's existing precedent for bundling the SPDX license
   list (`resources/spdx/licenses.json`) rather than embedding it in `domain/license.clj` -- both
   are large, externally-sourced, occasionally-revised reference data, not code.
3. **`vector->severity-v4 [vector-string]`** -- composes `parse-vector-v4`, `base-score-v4`, and the
   *existing* `severity-of-score` (no new v4-specific severity function needed, per Format
   research), nil-safe via `some->`.
4. Extend `osv.clj`'s `record-severity` with a fourth fallback tier: a `CVSS_V4`-typed
   `severity[]` entry, tried **before** `CVSS_V3`/`CVSS_V2` (a newer CVSS version's own assessment
   of the same vulnerability is the more refined one when more than one is present -- see Design),
   and before the final `:unknown`.

## Non-goals

- **Threat, Environmental, or Supplemental metric scoring.** Base only, matching the v2/v3 plans'
  own scope -- a vector's Threat/Environmental/Supplemental segments are parsed-and-ignored the
  same permissive way `parse-vector`/`parse-vector-v2` already handle v3/v2's Temporal segments.
- **Hand-deriving the MacroVector table, `EQ1..EQ6` rules, or interpolation logic from the
  specification's prose.** The risk of a transcription error silently producing a wrong score --
  one a user might act on for a `--fail-on-violations` gate -- is high enough that this plan
  requires porting the table and algorithm directly from FIRST's own reference implementation
  source, with the exact upstream commit/release recorded in a comment, not re-deriving them
  independently from the written spec.
- **A guarantee of first-try correctness given the algorithm's complexity.** Unlike v2/v3, where a
  couple of known-answer vectors were enough to give reasonable confidence, this plan's Verification
  section calls for broad cross-checking against the official online calculator (see Verification)
  before this is trusted in a report a user might act on.
- **A new `severity-of-score-v4`.** Format research confirms v4's qualitative scale is identical to
  v3's; the existing `severity-of-score` is reused directly.
- **CVSS v2** -- see the companion [dev/plans/cvss-v2-vector-parser.md](cvss-v2-vector-parser.md).

## Design

### `parse-vector-v4`

Requires the `CVSS:4.0/` prefix (any other version prefix, including `3.0`/`3.1`/no-prefix-at-all,
returns nil -- those belong to `parse-vector`/`parse-vector-v2` respectively), then parses the
remaining segments into a `METRIC:VALUE` map exactly like `parse-vector` does for v3 (permissive
skip of anything that doesn't split into exactly one `:`, covering Threat/Environmental/
Supplemental passthrough), and validates all eleven Base metric keys (`AV`, `AC`, `AT`, `PR`, `UI`,
`VC`, `VI`, `VA`, `SC`, `SI`, `SA`) against their recognized values.

### `base-score-v4` and the bundled MacroVector table

The score computation is structured as three private stages, each named after the specification's
own terminology so the implementation can be cross-referenced line-by-line against the reference
source during implementation and future review:

1. `equivalence-classes [metrics]` -- computes `EQ1..EQ6` per the spec's documented per-class rules.
2. `macrovector-score [eq-classes]` -- looks up the six-digit macrovector string in the bundled
   `resources/cvss/cvss-v4-macrovectors.edn` table (a flat map of macrovector string to nominal
   score, ported verbatim from the reference implementation, loaded once via a `delay`, the same
   pattern `adapter/license/spdx.clj` already uses for the bundled SPDX license list).
3. `interpolated-score [metrics eq-classes]` -- computes the neighbor macrovectors and the
   metric-distance interpolation per the spec's algorithm, refining the nominal score from stage 2
   into the vector's exact score.

`base-score-v4` composes the three and clamps/rounds the final result to `[0.0, 10.0]` at one
decimal place.

### `vector->severity-v4`

```clojure
(defn vector->severity-v4
  [vector-string]
  (some-> vector-string parse-vector-v4 base-score-v4 severity-of-score))
```

Note this reuses `severity-of-score` (the v3/v4-shared one), not a v4-specific function -- see
Goals/Non-goals.

### `osv.clj` integration and fallback ordering

```clojure
(defn- cvss-v4-vector
  [record]
  (some (fn [{:keys [type score]}] (when (= type "CVSS_V4") score)) (:severity record)))

(defn- record-severity
  [record]
  (or (get database-specific-severities
           (some-> record :database_specific :severity string/lower-case))
      (cvss/vector->severity-v4 (cvss-v4-vector record))
      (cvss/vector->severity (cvss-v3-vector record))
      (cvss/vector->severity-v2 (cvss-v2-vector record))
      :unknown))
```

`CVSS_V4` is tried **before** `CVSS_V3`/`CVSS_V2` -- when a record somehow carries more than one
CVSS version's assessment of the same vulnerability, the newest, most refined one should win. This
reorders the tier `CVSS_V2` (per [dev/plans/cvss-v2-vector-parser.md](cvss-v2-vector-parser.md))
added ahead of `CVSS_V3`; whichever of these two plans lands second should apply this ordering
change, since the tier order only matters once both v2 and v4 tiers coexist.

## Step-by-step implementation

### Step 1 -- `parse-vector-v4` (independently landable)

Add to `domain/cvss.clj`: the eleven-metric weight/value tables and `parse-vector-v4`, per Design.
This alone is low-risk and testable without the scoring algorithm existing yet.

### Step 2 -- Port the MacroVector table and scoring algorithm

- Create `resources/cvss/cvss-v4-macrovectors.edn`, transcribed directly from FIRST's reference
  implementation's own table (record the exact source commit/release in a comment at the top of the
  file, or in this plan's own history, so a future refresh can diff against it).
- Implement `equivalence-classes`, `macrovector-score`, `interpolated-score`, and `base-score-v4`
  per Design, cross-referencing the reference implementation's own function/variable names in
  comments where the mapping isn't obvious, to ease future auditing.

### Step 3 -- `vector->severity-v4` and `osv.clj` integration

Add `vector->severity-v4` (reusing `severity-of-score`) and extend `osv.clj`'s `record-severity`
with the `CVSS_V4` tier, reordering the fallback chain per Design if
[dev/plans/cvss-v2-vector-parser.md](cvss-v2-vector-parser.md) has already landed its own tier by
this point.

### Step 4 -- Tests

- `parse-vector-v4`: valid vector, rejects `CVSS:3.1/...`/`CVSS:2.0`-shaped/bare-no-prefix strings,
  rejects a vector missing a required metric.
- `base-score-v4`: **a broad sample (10+) of vectors spanning different equivalence-class
  combinations**, each cross-checked against the official online calculator's own output
  (https://www.first.org/cvss/calculator/4.0) -- not just one or two easy cases, given the
  algorithm's complexity and this plan's explicit Non-goal disclaiming first-try-correctness
  confidence from fewer checks. Store the vector-to-expected-score pairs as a fixture (e.g.
  `test/resources/cvss/v4-known-answers.edn`) so the set can be extended or re-verified quickly if
  the bundled table is ever refreshed.
- `vector->severity-v4`: nil for garbage/nil, correct severity for a valid vector.
- `osv_test.clj`: a case where only a `CVSS_V4` entry is present, and (once
  [dev/plans/cvss-v2-vector-parser.md](cvss-v2-vector-parser.md) has landed) a case confirming
  `CVSS_V4` wins over a `CVSS_V3`/`CVSS_V2` entry present on the same record.

### Step 5 -- Documentation

Update `README.md`'s OSV severity-fallback sentence to mention the `CVSS_V4` tier and its
before-v3/v2 precedence.

## File-by-file summary

| File | Change |
|---|---|
| `src/sbom_tool/domain/cvss.clj` | adds `parse-vector-v4`, `base-score-v4` (and its private `equivalence-classes`/`macrovector-score`/`interpolated-score` stages), `vector->severity-v4` |
| `resources/cvss/cvss-v4-macrovectors.edn` | **new** -- MacroVector lookup table, ported from the official reference implementation |
| `src/sbom_tool/adapter/vulnerability/osv.clj` | `record-severity` gains a `CVSS_V4` fallback tier, tried first among the CVSS tiers; reorders relative to `CVSS_V2`'s tier if that plan has already landed |
| `test/sbom_tool/domain/cvss_test.clj` | new v4 test cases |
| `test/resources/cvss/v4-known-answers.edn` | **new** -- vector-to-expected-score fixture pairs, sourced from the official calculator |
| `test/sbom_tool/adapter/vulnerability/osv_test.clj` | new case(s): `CVSS_V4`-only record, and (if v2 has landed) `CVSS_V4`-over-`CVSS_V3`/`CVSS_V2` precedence |
| `README.md` | extends the OSV severity-fallback sentence |

## Verification

- `bb test` -- all new/existing tests green, no network access required (pure, offline domain
  math/table lookup).
- **A much broader manual cross-check than v2/v3 required**, against the official calculator
  (https://www.first.org/cvss/calculator/4.0), across a deliberately varied sample of vectors
  covering different equivalence-class combinations -- not just one or two easy cases -- given the
  higher error surface of a table-plus-interpolation algorithm versus v2/v3's closed-form formulas.
  Recommend keeping the fixture from Step 4 scriptable so it can be re-run quickly if the bundled
  table is ever refreshed from a newer reference-implementation release.

## Risks / open questions

- **This is a meaningfully larger and more error-prone reimplementation than v2 or v3.** A
  closed-form formula (v2/v3) is easy to verify by hand against a spec's worked examples; a
  270-row lookup table plus a multi-step interpolation algorithm is not -- a subtle transcription
  error could produce a score that is wrong by a fraction of a point (affecting which severity
  bucket, and thus `--fail-on-violations`, a component lands in) without being obviously broken.
  Budget real review/testing time before trusting this in a report a user might act on; do not
  treat this plan's Step 2 as a quick port.
- **Consider a narrower first version.** An intermediate implementation that does `parse-vector-v4`
  plus a **MacroVector-only score** (Step 2's stage 2, skipping stage 3's interpolation refinement
  entirely -- i.e. reporting each macrovector's flat nominal score rather than the exact
  interpolated one) would land a much smaller, more auditable slice at the cost of some in-bucket
  precision (the reported score could be off by up to roughly the width of one macrovector's score
  band, though the resulting `::sbom/severity` keyword -- the only thing this tool's reports and
  policy gating actually consume -- would still usually land in the same bucket). Flagged as an
  open design question for whoever picks this plan up, not resolved here; if pursued, `base-score-v4`
  would still be free to add the interpolation refinement later without changing its signature.
- **Reference implementation drift.** FIRST has revised the official calculator's MacroVector table
  after initial v4.0 publication; this plan's bundled table will need periodic re-diffing against
  the live reference implementation, the same maintenance burden `resources/spdx/licenses.json`
  already has (refreshable via `-L`/`--spdx-license-list`, though this plan's table has no
  equivalent user-supplied override -- see Follow-ups).

## Follow-ups (explicitly out of scope here)

- A CLI/config override for the bundled MacroVector table path, mirroring
  `-L`/`--spdx-license-list`'s "bundled snapshot, but overridable" pattern, if the table's
  staleness ever becomes a real operational concern -- not needed for a first version.
- Full Environmental/Threat-adjusted v4 scoring, if a source ever provides Environmental-modified
  vectors this tool needs to score (today, no adapter has environmental data).
- Revisiting whether `database_specific.severity` should really outrank a `CVSS_V4` vector when a
  record carries both (Design keeps `database_specific.severity` first, as the v3/v2 plans already
  established, on the theory that it's a source-curated qualitative judgment rather than a raw
  computed score) -- and, among the three CVSS tiers themselves, whether `CVSS_V4` > `CVSS_V3` >
  `CVSS_V2` is really the right precedence, once real-world OSV data shows how often a single
  record actually carries more than one CVSS version for the same vulnerability. Today both are
  judgment calls with no observed data to confirm them against.
