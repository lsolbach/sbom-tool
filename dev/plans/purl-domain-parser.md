# Plan: A Shared Purl Parser in the Domain Layer

**Status:** implemented
**Date:** 2026-09-24
**Related:** [dev/plans/deps-dev-vulnerability-adapter.md](deps-dev-vulnerability-adapter.md)
(implemented; the original, adapter-private `parse-purl`), [dev/plans/osv-vulnerability-adapter.md](osv-vulnerability-adapter.md)
(proposed; updated by this plan to drop its own duplicate), [dev/plans/github-advisory-vulnerability-adapter.md](github-advisory-vulnerability-adapter.md)
(proposed; updated by this plan to drop its own duplicate), [dev/plans/nvd-vulnerability-adapter.md](nvd-vulnerability-adapter.md)
(cpe-keyed, does not parse purls, unaffected by this plan).

## Problem

Purl parsing -- percent-decoding, stripping `?qualifiers`/`#subpath`, splitting on the rightmost
unescaped `@` to separate the version, and joining a multi-segment namespace back into a single
qualified name -- is not a small, mechanical idiom. It is real, non-trivial logic with several
sharp edges (npm's `%40`-encoded scope, Maven's `group:artifact` convention versus everyone else's
`namespace/name`, Go's multi-segment import-path namespaces), already implemented once in
`adapter/vulnerability/deps_dev.clj`, and slated to be implemented two more times by the OSV and
GitHub Advisory Database plans -- the OSV plan's smaller `purl-has-version?` and the GitHub
Advisory Database plan's full `parse-purl` copy. Those two plans each justified the duplication by
pointing at this codebase's real precedent for hand-rolling small things per-namespace (the
babashka `JsonProcessingException` `Class/forName` fix, duplicated verbatim in `adapter/sbom/
cdx.clj` and `adapter/sbom/spdx.clj`) -- but that precedent is a 10-line, single-purpose
workaround with no independent logic to get wrong twice; purl parsing is meaningfully bigger and
riskier to fork three ways, and a purl is a component identifier format on the same footing as
`::sbom/purl`/`::sbom/cpe` in `domain/sbom.clj`, not something intrinsic to any one vulnerability
database's API. It belongs in the domain layer, implemented and tested once, and reused by every
adapter that needs it -- exactly the request behind this plan.

## Goals

1. A new `sbom-tool.domain.purl` namespace exposing `parse-purl` (full decomposition, the exact
   contract `deps_dev.clj`'s current private function already has) and `qualified-name` (the
   `namespace`/`name`-joining convention -- `:` for Maven, `/` for everything else with a
   namespace -- currently duplicated as `deps-dev-package-name` in `deps_dev.clj` and planned again
   as `github-package-name` in the GitHub Advisory Database plan).
2. A pure move, not a rewrite: identical parsing behavior to what `deps_dev.clj` already ships and
   what its existing tests already pin down -- this is a refactor, with no observable change to
   deps.dev's own results.
3. Retrofit the already-implemented deps.dev adapter to depend on the new namespace instead of its
   own private copy, and update the two still-proposed plans (OSV, GitHub Advisory Database) so
   their designs are written against the shared function from the start, rather than documenting
   duplication this plan is about to make unnecessary.
4. One place to fix a purl-parsing bug in the future, and one place (`domain/purl_test.clj`) that
   owns its test coverage -- every adapter that uses it inherits correctness rather than
   re-proving it.

## Non-goals

- Unifying each adapter's own external-vocabulary mapping tables (deps.dev's `purl-systems`:
  `pypi`->`pypi`, `cargo`->`cargo`; the GitHub Advisory Database plan's `github-ecosystem`:
  `pypi`->`pip`, `cargo`->`rust`). These encode what a *specific external API* calls a purl type,
  not what the purl type *is* -- genuinely different concerns that happen to share an input, and
  each table's values already disagree with each other's, so merging them would be actively wrong,
  not simplifying.
- Validating `:type` against the full [registered purl-types
  list](https://github.com/package-url/purl-spec) -- `parse-purl` stays permissive about `:type`
  (any string the purl body's first segment names), the same as today's `deps_dev.clj` behavior;
  it is each *adapter's* mapping table that decides which types it recognizes, not the parser.
- Changing `::sbom/purl`'s status as an opaque string anywhere in the canonical component model --
  `domain/component.clj`'s `component-identity`/`merge-components` and everything in
  `application/repository.clj` keep comparing/storing raw purl strings unchanged; only code that
  already needs the decomposed form (the vulnerability adapters) starts calling the new parser.
- The NVD adapter -- it is cpe-keyed and has no purl-parsing need (see its plan's own Non-goals on
  purl-to-CPE derivation, a separate and explicitly rejected idea); this plan does not touch it.
- A `clojure.spec.alpha` spec for the parsed-purl map. `domain/component.clj` -- the closest
  precedent for a domain namespace producing internal structured maps rather than validating
  external input -- has no specs of its own; `domain/license.clj`'s specs exist specifically to
  validate policy *files* crossing a trust boundary. A parsed purl never crosses such a boundary
  (its input, `::sbom/purl`, is already validated as a bare string by `domain/sbom.clj`), so no
  spec is added here, consistent with `component.clj`'s precedent rather than `license.clj`'s.

## Design

### What moves, and what stays put

`deps_dev.clj` today has four purl-related private helpers: `decode` (percent-decoding), `parse-
purl`, `deps-dev-package-name` (the namespace/name join), and `url-encode`. Only the first three
are about *parsing/rendering a purl* -- `url-encode` is about building a deps.dev HTTP request URL
from an already-rendered name, a transport concern with nothing to do with purl semantics, and
stays in `deps_dev.clj` (and will be duplicated locally again in the GitHub Advisory Database
adapter, whose own URL-building is unrelated to this plan).

`domain/purl.clj` gains:

- `parse-purl [purl]` -- identical contract to today's `deps_dev.clj` function: parses
  `pkg:type/namespace/name@version` into `{:type :namespace :name :version}` (`:namespace` nil
  when absent), discarding `?qualifiers`/`#subpath`, percent-decoding every component, and
  returning nil for anything not shaped like a well-formed, versioned purl (no `pkg:` scheme, no
  name, or no version -- an unversioned purl is exactly as "doesn't parse" as a non-purl string,
  which is what lets the OSV plan drop its separate `purl-has-version?` boolean check entirely and
  just inspect `(:version (purl/parse-purl p))` instead, see below).
- `qualified-name [{:keys [type namespace name]}]` -- renders `namespace`/`name` back into the
  single string convention each of this project's purl-consuming adapters needs to build an
  external system's package identifier: `namespace:name` when `type` is `"maven"`, `namespace/
  name` when `namespace` is present for any other type, or bare `name` when there is no namespace
  at all. This is `deps_dev.clj`'s current `deps-dev-package-name` and the GitHub Advisory Database
  plan's planned `github-package-name`, unified -- both were already this exact rule, just written
  twice.

### Migrating `deps_dev.clj` (the one already-implemented adapter)

- Add `[sbom-tool.domain.purl :as purl]` to its `:require`.
- Delete its private `decode`, `parse-purl`, and `deps-dev-package-name`.
- Replace every internal call to `parse-purl`/`deps-dev-package-name` with `purl/parse-purl`/
  `(purl/qualified-name parsed)`.
- `parse-purl` was public (not `defn-`) in `deps_dev.clj` specifically so `deps_dev_test.clj` could
  exercise it directly; once it delegates to `domain.purl/parse-purl`, that publicness no longer
  serves a purpose -- `deps_dev.clj` does not need to re-export it, since callers (and tests) that
  want to parse a purl should require `domain.purl` directly. Anything in `deps_dev.clj` that only
  ever passed a purl straight through to `purl/parse-purl` can stay exactly as it is otherwise;
  this is a delete-and-redirect, not a restructuring.

### Updating the two proposed adapter plans

- **OSV plan**: its "Purl handling" section currently designs a bespoke `purl-has-version?`
  boolean check specifically to avoid needing deps.dev's "full decomposition." With a shared
  `domain.purl/parse-purl` already paid for, that justification disappears -- the OSV adapter
  should just call `(purl/parse-purl p)` and check whether `:version` is non-nil, the same
  presence check `fetch-all-vulnerabilities`'s filtering step already needs to do either way. This
  plan removes `purl-has-version?` from the OSV plan entirely (see the accompanying edit).
- **GitHub Advisory Database plan**: its "Purl handling" section currently plans a private,
  duplicated `parse-purl` and a `github-package-name` join function. Both are replaced by direct
  calls to `domain.purl/parse-purl`/`domain.purl/qualified-name`; only `github-ecosystem` (the
  type-to-ecosystem-vocabulary table, a genuine per-adapter concern, see Non-goals) stays local to
  that adapter.
- Neither plan's actual behavior changes -- both were already going to parse purls exactly this
  way; only where the code that does it lives changes.

## Step-by-step implementation

### Step 1 -- New domain namespace

Create `src/sbom_tool/domain/purl.clj` with `parse-purl` and `qualified-name`, moved verbatim (in
behavior) from `deps_dev.clj`'s current private implementation, given a docstring in this
namespace's own voice (a component-identifier format, not a deps.dev concern) rather than
`deps_dev.clj`'s deps.dev-flavored one.

### Step 2 -- Migrate `deps_dev.clj`

- Require `sbom-tool.domain.purl`.
- Remove `decode`, `parse-purl`, `deps-dev-package-name`; redirect their call sites to
  `purl/parse-purl`/`purl/qualified-name`.
- Confirm `bb test` still passes unchanged (this step must not alter deps.dev's observable
  behavior at all).

### Step 3 -- Move the tests

- Move `deps_dev_test.clj`'s `parse-purl-test` cases to a new `test/sbom_tool/domain/purl_test.clj`
  (same cases: plain purl, percent-decoded npm scope, Maven `group:artifact` namespace, Go's
  multi-segment namespace, qualifiers/subpath discarded, no-version and non-purl both nil), calling
  `purl/parse-purl` instead of `deps-dev/parse-purl`.
- Add `qualified-name` cases to the same new test file (Maven joins with `:`, a namespaced non-
  Maven type joins with `/`, no namespace returns the bare name).
- `deps_dev_test.clj` keeps only what is still genuinely deps.dev's own (`map-advisory`,
  `fetch-vulnerabilities`'s unsupported-purl/no-network guarantee, the fixture-shape test) --
  it no longer needs its own `parse-purl-test`, since that logic now belongs to, and is fully
  covered by, `domain/purl_test.clj`.

### Step 4 -- Update the OSV and GitHub Advisory Database plan documents

Already done as part of this change (see the edits to `dev/plans/osv-vulnerability-adapter.md` and
`dev/plans/github-advisory-vulnerability-adapter.md` accompanying this plan): both now design
against `domain.purl/parse-purl`/`qualified-name` directly, with their own former duplicate-parser
sections and the "three near-duplicate `parse-purl` copies" risk/follow-up entries removed, since
this plan resolves that concern before either adapter is built.

## File-by-file summary

| File | Change |
|---|---|
| `src/sbom_tool/domain/purl.clj` | **new** -- `parse-purl`, `qualified-name` |
| `src/sbom_tool/adapter/vulnerability/deps_dev.clj` | requires `domain.purl`; deletes its own `decode`/`parse-purl`/`deps-dev-package-name` |
| `test/sbom_tool/domain/purl_test.clj` | **new** -- moved `parse-purl` cases plus new `qualified-name` cases |
| `test/sbom_tool/adapter/vulnerability/deps_dev_test.clj` | drops `parse-purl-test` (moved) |
| `dev/plans/osv-vulnerability-adapter.md` | drops `purl-has-version?`, designs against `domain.purl/parse-purl` |
| `dev/plans/github-advisory-vulnerability-adapter.md` | drops its own `parse-purl`/`github-package-name`, designs against `domain.purl` |

## Verification

- `bb test` -- all tests green, including the moved/renamed `domain/purl_test.clj` cases and
  `deps_dev_test.clj`'s reduced suite.
- Manual spot check: run the already-implemented `-D deps-dev` path against a real SBOM exactly as
  before this refactor and confirm byte-identical report output -- this step is a pure internal
  move and must not change what deps.dev's adapter reports.

## Risks / open questions

- **None material** -- this is a low-risk, mechanical extraction of already-implemented, already-
  tested logic, done before (not after) the two dependent adapters are built, which is the
  cheapest time to do it.

## Follow-ups (explicitly out of scope here)

- If the NVD adapter, or any future adapter, ever needs to render a purl-like string back out
  (rather than only parsing one), consider whether `qualified-name` generalizes further -- no
  concrete need for this exists today.
