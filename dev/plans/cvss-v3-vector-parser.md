# Plan: A Shared CVSS v3 Vector Parser in the Domain Layer

**Status:** implemented
**Date:** 2026-09-29
**Related:** [dev/plans/osv-vulnerability-adapter.md](osv-vulnerability-adapter.md) (implemented;
its Non-goals explicitly deferred "computing a numeric CVSS base score from OSV's
`severity[].score` vector strings," the gap this plan closes), [dev/plans/deps-dev-vulnerability-adapter.md](deps-dev-vulnerability-adapter.md)
(implemented; its private `cvss-severity` score-to-keyword mapping is retrofitted onto this plan's
shared namespace, unchanged in behavior), [dev/plans/purl-domain-parser.md](purl-domain-parser.md)
(implemented; the precedent this plan follows for extracting real, sharp-edged parsing logic into
a shared, once-tested domain namespace rather than duplicating it per adapter), [dev/plans/nvd-vulnerability-adapter.md](nvd-vulnerability-adapter.md)
(proposed; NVD's `GetCves` response already carries a numeric `baseScore` per CVSS version
directly, so it has no vector string to parse -- unaffected by this plan, see Non-goals).

## Problem

`domain/sbom.clj`'s `::sbom/severity` is a five-value keyword (`:unknown`/`:low`/`:medium`/`:high`/
`:critical`), and today exactly one adapter computes it from a raw CVSS score:
`adapter/vulnerability/deps_dev.clj`'s private `cvss-severity`, fed by deps.dev's own ready-made
`cvss3Score` numeric field. Google OSV (`adapter/vulnerability/osv.clj`, implemented per
[dev/plans/osv-vulnerability-adapter.md](osv-vulnerability-adapter.md)) has no such ready-made
number for most of what it aggregates: its `severity[]` array carries a *vector string* (e.g.
`"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"`), not a score, and today's `osv.clj` only reads
the qualitative `database_specific.severity` (`LOW`/`MODERATE`/`HIGH`/`CRITICAL`), falling back to
`:unknown` whenever that field is absent -- which it is for a real share of OSV's aggregated
sources (Maven, Debian, Alpine, and others that don't populate GHSA's `database_specific`
convention), even when those same records carry a perfectly good CVSS v3 vector the tool currently
throws away. This plan implements the CVSS v3 Base Score formula once, in the domain layer, so any
adapter holding a CVSS v3 vector string -- OSV today, any future one tomorrow -- can turn it into
the same canonical `::sbom/severity` keyword the rest of the tool already understands.

## Format research (done as part of this plan)

Verified against the published [CVSS v3.1 Specification Document](https://www.first.org/cvss/v3-1/specification-document)
(the authoritative source; v3.0 uses the same Base metrics and the same Base Score formula, see
"v3.0 vs v3.1" below) and the [OSV schema](https://ossf.github.io/osv-schema/)'s `severity[]`
field:

- **Vector string shape**: `CVSS:<version>/AV:<x>/AC:<x>/PR:<x>/UI:<x>/S:<x>/C:<x>/I:<x>/A:<x>`,
  optionally followed by Temporal/Environmental metrics this plan does not parse (see Non-goals).
  `<version>` is `"3.0"` or `"3.1"`. Order of the eight Base metrics is fixed by the spec, but this
  plan parses them as a `METRIC:VALUE` map rather than relying on position, so an unexpected order
  or an interleaved Temporal metric does not break parsing.
- **The eight Base metrics** and their official numerical values (Spec section 7.4, "Base Metrics
  Equations"):
  - `AV` (Attack Vector): `N`=0.85, `A`=0.62, `L`=0.55, `P`=0.2
  - `AC` (Attack Complexity): `L`=0.77, `H`=0.44
  - `PR` (Privileges Required): depends on `S` -- Scope Unchanged: `N`=0.85, `L`=0.62, `H`=0.27;
    Scope Changed: `N`=0.85, `L`=0.68, `H`=0.5
  - `UI` (User Interaction): `N`=0.85, `R`=0.62
  - `S` (Scope): `U` (Unchanged) or `C` (Changed) -- not itself weighted, but selects which `PR`
    table and which of two score formulas applies
  - `C`/`I`/`A` (Confidentiality/Integrity/Availability Impact): `H`=0.56, `L`=0.22, `N`=0.0
- **Base Score formula** (Spec section 7.4):
  ```
  ISCBase = 1 - [(1 - C) x (1 - I) x (1 - A)]
  Impact  = if Scope Unchanged: 6.42 x ISCBase
            if Scope Changed:   7.52 x (ISCBase - 0.029) - 3.25 x (ISCBase - 0.02)^15
  Exploitability = 8.22 x AV x AC x PR x UI
  BaseScore = 0.0                                             if Impact <= 0
            = Roundup(Minimum[(Impact + Exploitability), 10])           if Scope Unchanged
            = Roundup(Minimum[1.08 x (Impact + Exploitability), 10])    if Scope Changed
  ```
  `Roundup` is defined precisely (Spec Appendix A) to sidestep floating-point rounding surprises:
  multiply by 100000, round to the nearest integer, then round *up* to the nearest multiple of
  10000 before dividing back down to one decimal place -- never a plain `Math/round` to one
  decimal, which can round 4.02 down to 4.0 instead of up to 4.1.
- **Known-answer cross-checks** (worked by hand as part of this plan, both matching real,
  independently published scores): `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` scores **7.5** (matches
  NVD's own published Base Score for CVE-2020-8203, the lodash prototype pollution CVE already used
  as this project's OSV/deps.dev test fixture) and `AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H` scores
  **9.6** (the commonly-cited "Scope Changed, all-High" reference vector used across CVSS
  calculator test suites) -- both become this plan's primary `base-score` test cases.
- **v3.0 vs v3.1**: the Base Score formula and all eight Base metrics' numerical values are
  identical between the two versions; they differ only in Environmental/Modified-metric scoring
  and a documentation clarification of `Roundup`'s edge-case behavior that does not change any
  Base-only result this plan computes. This plan therefore accepts both `CVSS:3.0` and `CVSS:3.1`
  vectors through the same code path, recording which version was given without branching logic on
  it.
- **CVSS v2 and v4 vectors are structurally different formats** (different metric names, different
  formulas entirely) and are explicitly out of scope (see Non-goals) -- OSV's `severity[]` can
  carry `CVSS_V2` entries too, which this plan's parser correctly rejects (nil) rather than
  misinterpreting.

## Goals

1. A new `sbom-tool.domain.cvss` namespace exposing:
   - `parse-vector [vector-string]` -- a CVSS v3.0/v3.1 Base vector string to `{:version :av :ac
     :pr :ui :s :c :i :a}`, or nil for anything that isn't a complete, well-formed v3.0/3.1 Base
     vector (wrong/unsupported version prefix, a missing required metric, or an unrecognized
     value).
   - `base-score [metrics]` -- the parsed metrics to a numeric score in `[0.0, 10.0]`, implementing
     the Base Score formula verbatim, including the spec's exact `Roundup` behavior.
   - `severity-of-score [score]` -- a numeric score (or nil) to the canonical `::sbom/severity`
     keyword, using the same qualitative ranges NVD itself publishes (critical >= 9.0, high >=
     7.0, medium >= 4.0, low >= 0.1, else `:unknown`) -- moved here from `deps_dev.clj`'s current
     private `cvss-severity`, unchanged.
   - `vector->severity [vector-string]` -- composes the three above (`parse-vector` then
     `base-score` then `severity-of-score`), nil-safe throughout, for a caller that only wants the
     end severity and does not care about the intermediate score or metrics.
2. Retrofit `deps_dev.clj` to call `cvss/severity-of-score` instead of its own private
   `cvss-severity`, deleting the duplicate -- a pure move with no change to deps.dev's own
   observable behavior (it already had a ready-made numeric score; only where the score-to-keyword
   mapping lives changes), the same "one place to fix a bug in the future" payoff
   [dev/plans/purl-domain-parser.md](purl-domain-parser.md) already banked for purl parsing.
3. Extend `osv.clj`'s `record-severity` with a second-tier fallback: when a record has no
   `database_specific.severity`, look for a `severity[]` entry of type `CVSS_V3` and compute its
   severity via `cvss/vector->severity`, before finally giving up and returning `:unknown`. This
   recovers real severity information for OSV records sourced from ecosystems (Maven, Debian,
   Alpine, and others) that don't populate GHSA's `database_specific` convention but do carry a
   CVSS v3 vector.
4. One place, tested once (`domain/cvss_test.clj`), that any future adapter needing to turn a CVSS
   v3 vector into a severity can reuse without re-implementing the Base Score formula -- the same
   "shared domain logic, not a per-adapter concern" argument [dev/plans/purl-domain-parser.md](purl-domain-parser.md)
   already made for purls.

## Non-goals

- **CVSS v2 vector parsing.** A structurally different metric set and formula; OSV's `CVSS_V2`
  `severity[]` entries are simply not matched by this plan's `CVSS_V3`-only lookup in `osv.clj`
  (same "not covered, not an error" treatment `purl-systems`/`github-ecosystems` already give an
  unrecognized purl type).
- **CVSS v4 vector parsing.** A different vector format (`CVSS:4.0/...`) and an entirely
  restructured metric set (no `Scope`, an added Safety metric, a different scoring algorithm) --
  not requested, and not yet seen in this project's fixtures or adapters.
- **Temporal and Environmental metrics.** This plan parses and scores the eight Base metrics only;
  a vector carrying additional Temporal (`E`/`RL`/`RC`) or Environmental metrics is still parsed
  successfully (those extra `METRIC:VALUE` pairs are simply ignored, since `parse-vector` builds a
  map keyed by metric name rather than relying on positional/fixed-length parsing) but the score
  computed is always the Base Score, never a Temporal/Environmental-adjusted one.
- **Exposing the numeric base score in reports.** `::sbom/severity` stays the tool's only
  severity-shaped field end to end (`domain/sbom.clj`'s spec, every report/renderer); this plan
  only ever converts a vector down to that existing keyword, never adds a new numeric `:cvss-score`
  field to the canonical model or any report. A future plan could do that; not required here.
- **The NVD adapter.** [dev/plans/nvd-vulnerability-adapter.md](nvd-vulnerability-adapter.md)'s own
  API research already established that NVD's `GetCves` response carries `metrics.cvssMetricV31[]
  .cvssData.baseScore` directly -- a ready-made number, exactly like deps.dev's `cvss3Score` --
  so NVD has no vector string of its own to parse. It could still call `cvss/severity-of-score`
  for consistency once implemented (noted as a Follow-up), but that is that plan's decision to
  make, not this one's.
- **Validating a vector's Temporal/Environmental portion for well-formedness.** Since it is never
  parsed into the metrics map at all (previous bullet), this plan does not validate it either --
  `parse-vector` only requires the eight Base metrics to be present and valid; garbage after them
  does not invalidate an otherwise well-formed Base vector.

## Design

### `parse-vector [vector-string]`

Splits on `/`, requires the first segment to be exactly `CVSS:3.0` or `CVSS:3.1` (anything else --
`CVSS:2.0`, `CVSS:4.0`, a missing prefix, nil -- returns nil immediately), then parses the
remaining segments into a `METRIC:VALUE` map (segments that don't split into exactly one `:` are
skipped rather than failing the whole parse, covering the Temporal/Environmental passthrough from
Non-goals). Validates that all eight required Base metric keys (`AV`, `AC`, `PR`, `UI`, `S`, `C`,
`I`, `A`) are present with a value recognized by that metric's weight table; returns nil if any
are missing or unrecognized, since a partial Base vector cannot yield a meaningful score. On
success, returns `{:version "3.1" :av "N" :ac "L" :pr "N" :ui "N" :s "U" :c "N" :i "N" :a "H"}` --
the raw single-letter values, not yet resolved to their numeric weights (that resolution happens
in `base-score`, keeping `parse-vector`'s output easy to eyeball and test independently of the
scoring math).

### `base-score [metrics]`

Implements the formula from Format research verbatim:

1. Resolve `c`/`i`/`a`'s numeric weights, compute `iscbase`.
2. Compute `impact` -- branching on `:s` (`"U"` vs `"C"`) for the two different formulas.
3. Resolve `av`/`ac`/`pr`/`ui`'s numeric weights (`pr`'s table itself depends on `:s`), compute
   `exploitability`.
4. `0.0` when `impact <= 0`; otherwise `roundup` of `(impact + exploitability)` (Scope Unchanged)
   or `1.08 * (impact + exploitability)` (Scope Changed), each capped at `10.0` before rounding.
5. `roundup` is a private helper implementing the spec's exact integer-multiply-then-ceil-to-10000
   procedure (see Format research), not a generic decimal-rounding utility -- it is specific to
   this one spec-mandated behavior and stays private to this namespace.

### `severity-of-score [score]`

Moved verbatim (same thresholds, same `nil -> :unknown` treatment) from `deps_dev.clj`'s current
private `cvss-severity`; made public here since it is no longer specific to deps.dev.

### `vector->severity [vector-string]`

```clojure
(defn vector->severity
  [vector-string]
  (some-> vector-string parse-vector base-score severity-of-score))
```

Threads nil through every stage via `some->`, so a nil/malformed vector string yields nil (not an
exception) all the way through -- callers like `osv.clj` distinguish "this tier found nothing" from
"this tier errored," matching every other adapter's "a miss is not a failure" posture.

### `osv.clj` integration

`record-severity` (currently: `database_specific.severity` or `:unknown`) gains a middle tier:

```clojure
(defn- cvss-v3-vector
  [record]
  (some (fn [{:keys [type score]}] (when (= type "CVSS_V3") score)) (:severity record)))

(defn- record-severity
  [record]
  (or (get database-specific-severities
          (some-> record :database_specific :severity string/lower-case))
      (cvss/vector->severity (cvss-v3-vector record))
      :unknown))
```

`cvss-v3-vector` takes the *first* `CVSS_V3`-typed entry in `severity[]` when more than one is
present (rare in practice -- OSV records typically carry at most one CVSS v3 assessment); this is
a simplifying assumption, not a correctness guarantee that the first is authoritative, called out
in Risks.

## Step-by-step implementation

### Step 1 -- New domain namespace

Create `src/sbom_tool/domain/cvss.clj` with `parse-vector`, `base-score`, `severity-of-score`,
`vector->severity`, and the private weight tables/`roundup` helper, per Design above.

### Step 2 -- Retrofit `deps_dev.clj`

- Require `sbom-tool.domain.cvss`.
- Delete the private `cvss-severity`; replace its one call site (`map-advisory`) with
  `cvss/severity-of-score`.
- Confirm `bb test` still passes unchanged -- this step must not alter deps.dev's observable
  behavior at all (its `cvss3Score` was already a number; only where the number-to-keyword mapping
  lives changes).

### Step 3 -- Extend `osv.clj`

- Require `sbom-tool.domain.cvss`.
- Add `cvss-v3-vector` and extend `record-severity` per Design above.
- No change to `osv.clj`'s public surface (`map-vulnerability`, `fetch-all-vulnerabilities`,
  `read-api-key`, `auth-headers` all keep their current contracts) -- only `record-severity`'s
  internal fallback chain grows a tier.

### Step 4 -- Tests

- New `test/sbom_tool/domain/cvss_test.clj`:
  - `parse-vector`: a valid 3.1 vector, a valid 3.0 vector (same metrics, different prefix,
    same resulting map modulo `:version`), rejects `CVSS:2.0/...` and `CVSS:4.0/...` and a bare
    garbage string and nil, rejects a vector missing a required Base metric (e.g. no `A:`).
  - `base-score`: the two known-answer vectors from Format research -- `AV:N/AC:L/PR:N/UI:N/S:U/
    C:N/I:N/A:H` -> `7.5`, `AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H` -> `9.6` -- plus the `Impact <= 0`
    edge case (`.../S:U/C:N/I:N/A:N` -> `0.0`).
  - `severity-of-score`: the same threshold cases `deps_dev_test.clj`'s current (indirect, via
    `map-advisory-test`) coverage already implies -- nil -> `:unknown`, and one representative value
    in each of the four scored buckets.
  - `vector->severity`: nil for a garbage/nil vector string, the correct keyword for a valid one
    (composing the above, so this is a thin integration check rather than re-testing the math).
- Update `test/sbom_tool/adapter/vulnerability/deps_dev_test.clj`: no case changes expected (it
  already only asserts on public `map-advisory`'s output, never on the now-deleted private
  `cvss-severity` directly), but re-run to confirm.
- Update `test/sbom_tool/adapter/vulnerability/osv_test.clj`: add a case where
  `database_specific.severity` is absent but `severity[]` carries a `CVSS_V3` vector -- asserts the
  computed severity, not `:unknown` -- using the lodash fixture's own existing vector
  (`test/resources/osv/vulnerability.json`'s `severity[0].score`, which per Format research already
  scores `7.5`/`:high`, so the existing fixture needs no changes, only a new assertion against it
  with `database_specific` `dissoc`-ed).

## File-by-file summary

| File | Change |
|---|---|
| `src/sbom_tool/domain/cvss.clj` | **new** -- `parse-vector`, `base-score`, `severity-of-score`, `vector->severity` |
| `src/sbom_tool/adapter/vulnerability/deps_dev.clj` | requires `domain.cvss`; deletes its own private `cvss-severity`, redirects to `cvss/severity-of-score` |
| `src/sbom_tool/adapter/vulnerability/osv.clj` | requires `domain.cvss`; `record-severity` gains a CVSS-v3-vector fallback tier before `:unknown` |
| `test/sbom_tool/domain/cvss_test.clj` | **new** |
| `test/sbom_tool/adapter/vulnerability/osv_test.clj` | new case: severity computed from `severity[]` when `database_specific.severity` is absent |
| `README.md` | one-sentence update to the OSV section noting the CVSS-vector fallback (see Risks for what stays a documented gap) |

## Verification

- `bb test` -- all new/existing tests green, no network access required (this is pure, offline
  domain math).
- Manual spot check against a real, independently published CVSS v3.1 score not already used as a
  test fixture (e.g. look up a recent CVE's NVD page, feed its vector string through
  `cvss/base-score`), confirming the computed score matches NVD's own published figure to one
  decimal place.
- Manual, network-connected check (mirroring the OSV plan's own): run `-D osv -r vulnerabilities -o
  markdown` against an SBOM containing a package whose OSV record has no `database_specific.
  severity` but does carry a `CVSS_V3` vector (a Maven or Debian-sourced advisory is a good
  candidate), and confirm the reported severity is no longer `:unknown`.

## Risks / open questions

- **First-`CVSS_V3`-entry-wins is a simplifying assumption**, not a documented OSV guarantee, for
  the rare case where `severity[]` carries more than one `CVSS_V3` entry (e.g. a record annotated
  by two different upstream sources). Acceptable for a first version; revisit if it proves wrong
  in practice.
- **A `CVSS score of exactly 0.0` still maps to `:unknown`**, the same pre-existing conflation
  `deps_dev.clj`'s `cvss-severity` already has (NVD's own qualitative scale has a distinct "None"
  rating for `0.0`, which this tool's `::sbom/severity` keyword set has no slot for) -- not
  introduced by this plan, just inherited unchanged by the move to `domain.cvss`.
- **v3.0/v3.1 conflation**: this plan deliberately treats both versions identically for Base
  scoring (see Format research) rather than branching on `:version` -- correct for every Base-only
  computation, but would need revisiting if a future plan ever wants Environmental/Modified scoring
  for one version but not the other.

## Follow-ups (explicitly out of scope here)

- Reusing `cvss/severity-of-score` in the NVD adapter, once implemented, for consistency with how
  deps.dev and OSV now derive severity from a numeric score -- NVD gets `baseScore` directly, so
  it would only need `severity-of-score`, not `parse-vector`/`base-score`.
- CVSS v2 and v4 vector parsing, if a future data source ever makes v2/v4-only severity data
  otherwise unrecoverable (today, every adapter either has a direct score/qualitative severity, or
  a CVSS v3 vector as the next-best fallback) -- now planned separately in
  [dev/plans/cvss-v2-vector-parser.md](cvss-v2-vector-parser.md) (a small, closed-form extension)
  and [dev/plans/cvss-v4-vector-parser.md](cvss-v4-vector-parser.md) (a much larger effort, since
  v4 scoring is table-driven rather than a formula).
- Exposing the numeric base score itself (not just the derived keyword) in the `vulnerabilities`
  report, for a reader who wants more granularity than five buckets.
