# Plan: Extending the CVSS Domain Namespace to CVSS v2

**Status:** implemented
**Date:** 2026-09-29
**Related:** [dev/plans/cvss-v3-vector-parser.md](cvss-v3-vector-parser.md) (implemented; the
`sbom-tool.domain.cvss` namespace and `parse-vector`/`base-score`/`severity-of-score`/
`vector->severity` shape this plan extends with a v2-specific sibling set of functions, following
the same pattern), [dev/plans/cvss-v4-vector-parser.md](cvss-v4-vector-parser.md) (proposed; the
other CVSS version named in the same request, planned separately since v4's scoring algorithm is a
fundamentally larger effort than this plan's closed-form v2 formula), [dev/plans/osv-vulnerability-adapter.md](osv-vulnerability-adapter.md)
(implemented; `osv.clj`'s `record-severity` is the first, and so far only, caller this plan
extends with a new fallback tier).

## Problem

`domain/cvss.clj` (per [dev/plans/cvss-v3-vector-parser.md](cvss-v3-vector-parser.md), implemented)
only understands CVSS v3.0/v3.1 Base vectors. OSV's `severity[]` array can also carry a
`CVSS_V2`-typed entry (a bare vector like `"AV:N/AC:L/Au:N/C:N/I:N/A:C"`, no version prefix at
all), which `osv.clj`'s current `cvss-v3-vector`/`record-severity` simply never looks at -- only
`CVSS_V3`-typed entries are matched. A record whose only machine-readable severity signal is a
CVSS v2 vector (common for older advisories, and for some ecosystems/sources that never adopted
v3) still reports `:unknown`, even though a real, if superseded, score is sitting right there. This
plan extends `domain.cvss` to close that specific, narrower gap -- CVSS v2's Base Score is a
closed-form arithmetic formula, structurally simpler than v3's (no Scope branch) and vastly simpler
than v4's macrovector-table algorithm (see the companion [cvss-v4-vector-parser.md](cvss-v4-vector-parser.md)),
so this is a small, low-risk follow-up rather than a large reimplementation effort.

## Format research (done as part of this plan)

Verified against NVD's [CVSS v2 Complete Documentation](https://nvd.nist.gov/vuln-metrics/cvss/v2-calculator)
and FIRST's ["A Complete Guide to the Common Vulnerability Scoring System Version 2.0"](https://www.first.org/cvss/v2/guide):

- **Vector string shape**: unlike v3/v4, a CVSS v2 vector carries **no version prefix at all** --
  `AV:L/AC:H/Au:N/C:N/I:N/A:C`, optionally followed by Temporal (`E`/`RL`/`RC`) or Environmental
  metrics this plan does not parse (same Non-goal as the v3 plan). This is the one real parsing
  complication versus v3: `domain.cvss/parse-vector` dispatches on a `CVSS:x.y/` prefix that a v2
  vector simply doesn't have, so a v2-specific entry point is needed rather than teaching the
  existing one to also recognize a bare, unprefixed string (see Design).
- **Six Base metrics** -- no Scope, no Attack Requirements (both postdate v2):
  - `AV` (Access Vector): `L`=0.395, `A`=0.646, `N`=1.0
  - `AC` (Access Complexity): `H`=0.35, `M`=0.61, `L`=0.71
  - `Au` (Authentication): `M`=0.45, `S`=0.56, `N`=0.704
  - `C`/`I`/`A` (Confidentiality/Integrity/Availability Impact): `N`=0.0, `P`=0.275, `C`=0.660 --
    note these numeric values genuinely differ from v3's same-letter `C`/`I`/`A` weights
    (`N`=0.0, `L`=0.22, `H`=0.56), so v2 needs its own weight table, not a reuse of v3's.
- **Base Score formula** (structurally simpler than v3 -- one formula, no Scope-changed branch):
  ```
  Impact         = 10.41 x (1 - (1-C) x (1-I) x (1-A))
  Exploitability = 20 x AV x AC x Au
  f(Impact)      = 0 if Impact == 0, else 1.176
  BaseScore      = Round((0.6 x Impact + 0.4 x Exploitability - 1.5) x f(Impact), 1 decimal place)
  ```
  Rounding is a plain "round to nearest tenth" -- verified against NVD's own worked examples, none
  of which exhibit the floating-point edge case v3's spec Appendix A calls out `Roundup` to guard
  against, so no v2-specific analogue of that helper is needed.
- **Severity buckets differ from v3/v4, and this is the plan's central design point**: CVSS v2's
  own qualitative scale (NVD's pre-v3 severity ranking, still documented on NVD's CVSS v2
  calculator page) has only **three** bands -- Low 0.0-3.9, Medium 4.0-6.9, High 7.0-10.0 -- there
  is no v2 "Critical." Reusing `domain.cvss/severity-of-score`'s existing v3 thresholds unchanged
  against a v2 score would be a real correctness bug: a v2 score of, say, 9.5 would come back
  `:critical` under v3's `>= 9.0` threshold, even though CVSS v2 itself has no rating that severe
  beyond "High." A v2 score needs its own, distinct score-to-severity mapping.
- **Known-answer cross-check** (worked by hand, matching NVD's own published CVSS v2 Base Score for
  a well-known CVE): `AV:N/AC:L/Au:N/C:C/I:C/A:C` scores **10.0** (the maximal "network,
  low-complexity, no-auth, complete/complete/complete impact" vector, the CVSS v2 equivalent of the
  v3 plan's scope-changed reference vector, used across v2 calculator test suites) -- this plan's
  primary `base-score-v2` test case, alongside a mid-range vector for the `:medium` bucket.

## Goals

1. Extend `sbom-tool.domain.cvss` with a v2-specific sibling set of functions, mirroring the v3
   quartet's shape exactly:
   - `parse-vector-v2 [vector-string]` -- a bare (no `CVSS:` prefix) v2 Base vector string to
     `{:av :ac :au :c :i :a}`, or nil if any of the six required Base metrics is missing or
     carries an unrecognized value. No `:version` key (unlike v3's parsed map) -- a v2 vector
     carries no version marker to record.
   - `base-score-v2 [metrics]` -- the parsed metrics to a numeric score in `[0.0, 10.0]`,
     implementing the v2 Base Score formula verbatim.
   - `severity-of-score-v2 [score]` -- v2's own three-bucket qualitative scale (`:high` >= 7.0,
     `:medium` >= 4.0, `:low` >= 0.1, else `:unknown`) -- **deliberately never returns
     `:critical`**, a distinct function from `severity-of-score`, not a parameterized/shared one
     (see Design for why).
   - `vector->severity-v2 [vector-string]` -- composes the three above, nil-safe via `some->`,
     mirroring `vector->severity` exactly.
2. Extend `osv.clj`'s `record-severity` with a third fallback tier: a `CVSS_V2`-typed
   `severity[]` entry, tried after the existing `database_specific.severity` and `CVSS_V3` tiers
   and before the final `:unknown`, scored via `vector->severity-v2` (never `vector->severity`,
   which would apply the wrong version's thresholds).
3. One place, tested once, for any future adapter that needs to turn a CVSS v2 vector into a
   severity -- a prospective NVD adapter reading a pre-v3-era CVE (NVD kept publishing v2 scores
   alongside v3 for years after v3's 2015 release) is the most likely future beneficiary, per
   [dev/plans/nvd-vulnerability-adapter.md](nvd-vulnerability-adapter.md)'s own API research noting
   NVD's `metrics` object can carry `cvssMetricV2` entries alongside v3/v4 ones.

## Non-goals

- **Auto-detecting a vector's CVSS version from its shape alone.** `parse-vector-v2` is only ever
  invoked by a caller that already knows (from context -- e.g. `severity[].type == "CVSS_V2"`)
  that the string is a v2 vector; it does not attempt to distinguish a genuine v2 vector from a
  malformed/prefix-stripped v3 one by inspecting metric keys. This mirrors how `parse-vector`
  (v3) is only ever handed a string a caller already knows is `CVSS_V3`-typed.
- **CVSS v2 Temporal/Environmental scoring.** Base only, matching the v3 plan's own scope.
- **Changing `severity-of-score`'s existing (v3) thresholds or its current callers**
  (`deps_dev.clj`, `osv.clj`'s `CVSS_V3` tier) -- this plan adds a sibling function; it does not
  touch the existing one.
- **CVSS v4** -- see the companion [dev/plans/cvss-v4-vector-parser.md](cvss-v4-vector-parser.md).
- **A unified/parameterized `severity-of-score` taking a version argument.** Two small,
  clearly-named functions are safer here than one parameterized one that a caller could pass the
  wrong version flag to -- consistent with this codebase's existing preference for keeping
  per-format vocabulary tables separate rather than force-unifying them (e.g. `purl-systems`
  versus `github-ecosystems` staying distinct per [dev/plans/purl-domain-parser.md](purl-domain-parser.md)'s
  own Non-goals, rather than one shared purl-type-to-external-name table).

## Design

### Recognizing a v2 vector

Rather than have `parse-vector` guess whether a prefix-less string is a v2 vector, `parse-vector-v2`
is a wholly separate function: it splits `vector-string` on `/`, parses every `METRIC:VALUE`
segment into a map (segments that don't split into exactly one `:` are skipped, the same permissive
Temporal/Environmental passthrough `parse-vector` already uses for v3), and requires exactly the
six Base keys (`AV`, `AC`, `Au`, `C`, `I`, `A`) to be present with a value recognized by that
metric's weight table -- no prefix check at all, since a v2 vector has none. It is called only from
a context that already knows it is looking at a `CVSS_V2`-typed entry (`osv.clj`'s `severity[]`
dispatch), symmetric with how `parse-vector` is only ever reached from a `CVSS_V3`-typed context.

### `base-score-v2`

Implements the formula from Format research verbatim -- notably simpler than v3's `base-score`
(one formula, no Scope branch, no exponentiation, a plain round-to-nearest-tenth rather than v3's
spec-mandated integer `roundup`), so no shared helper with `base-score` is introduced; the two stay
independent, small functions.

### `severity-of-score-v2`

A new, v2-specific three-bucket mapping, kept as its own top-level function rather than a
parameterized variant of `severity-of-score` -- see Non-goals for why a second small function is
preferred here over unifying the two behind a version flag.

### `vector->severity-v2`

```clojure
(defn vector->severity-v2
  [vector-string]
  (some-> vector-string parse-vector-v2 base-score-v2 severity-of-score-v2))
```

### `osv.clj` integration

```clojure
(defn- cvss-v2-vector
  [record]
  (some (fn [{:keys [type score]}] (when (= type "CVSS_V2") score)) (:severity record)))

(defn- record-severity
  [record]
  (or (get database-specific-severities
           (some-> record :database_specific :severity string/lower-case))
      (cvss/vector->severity (cvss-v3-vector record))
      (cvss/vector->severity-v2 (cvss-v2-vector record))
      :unknown))
```

`CVSS_V3` stays tried before `CVSS_V2` -- a newer CVSS version's assessment of the same
vulnerability is generally considered more refined than an older one, so when a record somehow
carries both, the v3 one wins, consistent with treating v2 as the last-resort fallback its
deprecated status warrants.

## Step-by-step implementation

### Step 1 -- Extend `domain/cvss.clj`

Add `parse-vector-v2`, `base-score-v2`, `severity-of-score-v2`, `vector->severity-v2`, and the
private v2 weight tables (`av-weights-v2`, `ac-weights-v2`, `au-weights-v2`, `cia-weights-v2` --
named distinctly from, and never shared with, the existing v3 tables, since the numeric values
genuinely differ for overlapping-looking metric letters) per Design above.

### Step 2 -- Extend `osv.clj`

Add `cvss-v2-vector` and extend `record-severity`'s fallback chain per Design above. No change to
`osv.clj`'s public surface otherwise.

### Step 3 -- Tests

- Extend `test/sbom_tool/domain/cvss_test.clj` with a `parse-vector-v2`/`base-score-v2`/
  `severity-of-score-v2`/`vector->severity-v2` section: the known-answer `10.0` vector, a mid-range
  vector landing in `:medium`, rejection of a vector missing a required metric or carrying a `S`/
  `AT`-style v3/v4-only key by itself (still just "missing a required v2 metric" from
  `parse-vector-v2`'s point of view), and an explicit assertion that no score this function is
  fed ever returns `:critical` (documenting the three-bucket guarantee from Format research as a
  test, not just a docstring).
- Extend `test/sbom_tool/adapter/vulnerability/osv_test.clj` with a case where a record has neither
  `database_specific.severity` nor a `CVSS_V3` entry, but does carry a `CVSS_V2` one -- asserts the
  computed (non-`:critical`-capped) severity.

### Step 4 -- Documentation

Update `README.md`'s OSV section's severity-fallback sentence (last touched by
[dev/plans/cvss-v3-vector-parser.md](cvss-v3-vector-parser.md)) to mention the CVSS v2 tier as the
third and final fallback before `:unknown`.

## File-by-file summary

| File | Change |
|---|---|
| `src/sbom_tool/domain/cvss.clj` | adds `parse-vector-v2`, `base-score-v2`, `severity-of-score-v2`, `vector->severity-v2` and private v2 weight tables |
| `src/sbom_tool/adapter/vulnerability/osv.clj` | `record-severity` gains a `CVSS_V2` fallback tier, tried after `CVSS_V3` and before `:unknown` |
| `test/sbom_tool/domain/cvss_test.clj` | new v2 test cases |
| `test/sbom_tool/adapter/vulnerability/osv_test.clj` | new case: severity computed from a `CVSS_V2`-only record |
| `README.md` | extends the OSV severity-fallback sentence |

## Verification

- `bb test` -- all new/existing tests green, no network access required (pure, offline domain
  math, same as the v3 plan).
- Manual spot check against a real, independently published CVSS v2 score not already used as a
  test fixture (NVD still publishes v2 scores alongside v3/v4 for CVEs old enough to predate v3),
  confirming the computed score and severity bucket both match.

## Risks / open questions

- **Reviving a deprecated scoring system.** CVSS v2 has been superseded since 2015; a v2-only
  severity is inherently a weaker signal than a v3 or v4 one for the same vulnerability -- but
  still strictly more informative than `:unknown` when it is the only signal a record carries,
  which is the only case this plan's fallback tier ever activates.
- **The same "score of exactly `0.0` maps to `:unknown`, not a genuine `:none` rating" conflation**
  the v3 plan already accepted for its own thresholds, inherited here unchanged for v2's.

## Follow-ups (explicitly out of scope here)

- If the NVD adapter (per [dev/plans/nvd-vulnerability-adapter.md](nvd-vulnerability-adapter.md))
  is ever built and a CVE has only a `cvssMetricV2` entry (no v3/v4), this plan's
  `severity-of-score-v2`/`base-score-v2` are directly reusable there without modification.
