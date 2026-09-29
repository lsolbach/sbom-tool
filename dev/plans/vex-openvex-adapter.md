# Plan: OpenVEX as the First VEX Adapter, Integrated into Vulnerability Reports

**Status:** implemented
**Date:** 2026-09-29
**Related:** [dev/ideas.md](../ideas.md) ("VEX/OpenVEX" -- "Read VEX information" / "Use VEX
information in vulnerability reports"), [dev/plans/deps-dev-vulnerability-adapter.md](deps-dev-vulnerability-adapter.md)
and [dev/plans/github-advisory-vulnerability-adapter.md](github-advisory-vulnerability-adapter.md)
(the existing vulnerability adapters, whose "map an external format to the canonical model, wire
into repository/report/CLI" shape this plan reuses -- though VEX itself is not a vulnerability
*source*, see Design), [dev/plans/purl-domain-parser.md](purl-domain-parser.md) (the shared
`domain.purl` parser this plan does **not** need, since matching is done against
`::sbom/identifiers` directly, see Design).

## Problem

Today the tool only knows the exploitability signal a vulnerability source gives it (SBOM-embedded
`::sbom/vulnerability` records, or an opt-in live lookup via deps.dev/GitHub Advisory DB) and a
static policy (`:max-severity`/`:ignored`, see [domain/vulnerability.clj](../../src/sbom_tool/domain/vulnerability.clj)).
Neither can express a supplier's own, per-product exploitability assessment -- "this CVE affects
the package in general, but not *our* build of it, because the vulnerable code path is never
reached." That assessment is exactly what VEX (Vulnerability Exploitability eXchange) documents
carry, and it is the standard way to suppress a scanner/SBOM false positive without hand-editing a
local policy file every time. `dev/ideas.md` names VEX/OpenVEX as a wanted feature; this plan picks
[OpenVEX](https://github.com/openvex/spec) as the format to implement first -- it is the simplest,
JSON-based VEX format, and the only one named in the task.

## Format research (done as part of this plan)

Verified against the [OpenVEX spec](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md)
and its JSON schema:

- A document is `{"@context": "...", "@id": "...", "author": "...", "timestamp": "...",
  "version": 1, "statements": [...]}`. Only `statements` matters for this tool; the document-level
  metadata (author, timestamp) is not surfaced in reports for now (see Non-goals).
- Each statement is `{"vulnerability": {"name": "CVE-2023-1234", "aliases": ["GHSA-..."]},
  "products": [...], "status": "not_affected", "justification": "vulnerable_code_not_present",
  "status_notes": "...", "timestamp": "..."}`.
  - `status` is one of exactly four values: `not_affected`, `affected`, `fixed`,
    `under_investigation`.
  - `justification` is only meaningful (and only valid per the schema) when `status` is
    `not_affected`, one of five enum values: `component_not_present`,
    `vulnerable_code_not_present`, `vulnerable_code_not_in_execute_path`,
    `vulnerable_code_cannot_be_controlled_by_adversary`, `inline_mitigations_already_exist`.
  - `vulnerability.aliases` lets a statement written against a `GHSA-*` id (or vice versa) still
    match a report that surfaces the `CVE-*` id, or the reverse -- both of the tool's existing
    vulnerability adapters already prefer a CVE alias when one exists (see the two plans linked
    above), so alias-aware matching here is what makes VEX actually line up with what reports show.
  - **`products`** is where most of the real-world variance is: each entry is an object that
    identifies a product by `@id` (an IRI -- in practice this is very often a bare purl string,
    per the spec's own examples), by an `identifiers` map (`purl` and/or `cpe23` keys, per the
    schema), or by `hashes`. Some early real-world documents (and a few spec example snippets)
    use a bare string instead of `{"@id": "..."}`. Products may also carry a nested
    `subcomponents` array of the same shape, for statements scoped to a component *inside* a
    product rather than the product itself.
- No batching/pagination/auth concerns at all -- unlike the two existing adapters, this is a pure
  local-file format with no network involved.

## Goals

1. Let users opt into applying VEX statements to vulnerability reports via a new `--vex-path`
   option pointing at a directory of OpenVEX documents (`*.vex.json`) -- multiple documents (e.g.
   one per supplier) are read and merged, mirroring how SBOMs are read from `--input-path`.
2. Show each vulnerability's resolved VEX status (and, for `not_affected`, its justification) in
   the existing component-level vulnerability report, without changing that report's shape beyond
   additive fields.
3. Make a matching `not_affected`/`fixed` statement actually suppress that vulnerability from
   `--fail-on-violations`/the `blocked-vulnerabilities` report -- the real-world point of VEX --
   while never suppressing it for a component no statement actually names, and never letting one
   supplier's stale `not_affected` claim override another's `affected` claim for the same
   product+vulnerability.
4. Fail loudly on a malformed VEX file the user explicitly pointed `--vex-path` at (it's a local,
   fully-user-controlled input, like an SBOM file), but stay fully offline and require no new
   runtime dependency (matches the existing `cheshire`/`babashka.fs` usage already in
   `adapter/sbom/cdx.clj`).

## Non-goals

- CSAF VEX or any second VEX format. Only one format is asked for; no `--vex-format`-style dispatch
  is added preemptively (see Design for why the existing `--vulnerability-source` multimethod
  pattern is *not* mirrored here).
- `products[].subcomponents` matching -- only top-level `products[]` entries are matched. A rarer,
  more advanced case than most real-world OpenVEX documents in the wild use.
- Surfacing document-level metadata (`author`, `timestamp`, `@id`) anywhere in reports.
- Making the flat, cross-SBOM `blocked-vulnerabilities`/`vulnerability-summary` machinery resolve
  `::sbom/affected` component ids back to purls *per source document* -- VEX-awareness for
  `blocked-vulnerabilities` is achieved indirectly instead (see Design), which is sufficient for
  goal 3 without that resolution work.
- Generating/writing VEX documents -- this tool only ever consumes them.
- Any change to how `component-report`/`consolidated-component-vulnerabilities` behave when no
  `--vex-path` is given -- VEX must be fully inert by default, the same way `--vulnerability-source
  none` keeps the tool offline by default today.

## Design

### Where VEX fits: an overlay on the report, not a vulnerability source

Unlike deps.dev/GitHub Advisory DB, VEX does not add new vulnerabilities -- it re-labels
vulnerabilities that are already known (SBOM-embedded or externally looked up) for specific
products. It therefore does not belong in `:external-vulnerabilities` (a purl -> vulnerabilities
map); instead it is its own top-level piece of loaded state, `:vex-statements` in `repo/state` (a
flat vector of canonical statements, format-and-source-agnostic, the same "flatten everything
before storing" choice `:external-vulnerabilities`/`:policies` already make), consulted at
report-generation time against whichever component/vulnerability pair is being rendered.

### Canonical statement model: `sbom-tool.domain.vex` (new namespace)

Pure domain logic, independent of any SBOM document -- VEX is a cross-cutting overlay, exactly
like a policy (`domain/license.clj`/`domain/vulnerability.clj`'s own policy specs are the
precedent, not `domain/sbom.clj`). Canonical shape, spec'd with `clojure.spec.alpha` mirroring
`domain/vulnerability.clj`'s `::exemption`/`::policy` style:

```clojure
{:vulnerability-id "CVE-2023-1234"            ;; required
 :aliases ["GHSA-...."]                       ;; optional
 :status :not-affected                        ;; :affected :not-affected :fixed :under-investigation
 :justification :vulnerable-code-not-present  ;; only meaningful for :not-affected
 :status-notes "..."                          ;; optional free text
 :purls #{"pkg:npm/foo@1.0.0"}                ;; product identifiers this statement scopes to
 :cpes #{"cpe:2.3:..."}}
```

Functions:
- `matching-statements [statements component vulnerability-id]` -- statements whose
  `:vulnerability-id`/`:aliases` match `vulnerability-id` (case-insensitive, since CVE/GHSA ids are
  conventionally uppercase but not guaranteed to be typed that way) **and** whose `:purls`/`:cpes`
  intersect `component`'s `::sbom/identifiers` -- purl checked first, then cpe, the same
  preference `domain/component.clj/component-identity` already applies for the same reason (purl
  is the stronger, ecosystem-qualified signal).
- `vex-entry [statements component vulnerability-id]` -- resolves `matching-statements` to a single
  effective `{:status :justification :notes}`, or nil when nothing matches. When more than one
  statement matches (e.g. two suppliers' documents), the **most conservative status wins**:
  precedence `:affected` > `:under-investigation` > `:fixed` > `:not-affected`. This means a stale
  or overly-optimistic `not_affected` claim can never silently suppress a genuine `affected` claim
  from another document -- ambiguity always favors safety, not convenience.
- `exempted? [vex-entry]` -- true iff `(:status vex-entry)` is `:not-affected` or `:fixed`.

### New adapter namespace: `sbom-tool.adapter.vex.openvex`

Structured like `adapter/sbom/cdx.clj`'s directory-of-files reading (**fail loud** on a malformed
file under an explicitly-given path, warn-only on an empty directory) -- deliberately *not* the
two existing vulnerability adapters' warn-and-continue style, because those guard against network
flakiness on a resource the user didn't directly point at, whereas a VEX file the user named via
`--vex-path` is exactly as much "their input" as an SBOM file.

- `vex-files [path]` -- `(fs/glob path "**{.vex.json}")`, the same pattern
  `cdx-files`/`spdx-files` already use for their own extensions.
- `read-vex-document [filename]` -- slurp + `cheshire/parse-string keyword`, throwing
  `:vex-file-not-found`/`:malformed-vex-json` ex-info on failure (mirrors `cdx.clj/read-json`
  exactly, including its babashka `JsonProcessingException` `Class/forName` fix, since this
  namespace must also load under babashka per the project's existing launcher).
- `product-identifiers [product]` -- extracts `{:purl :cpe}` from one OpenVEX `products[]` entry:
  prefers `:identifiers :purl`/`:cpe23` when present; else, for a bare `@id` string (or a product
  given as a plain string, per Format research), infers by its `pkg:`/`cpe:` prefix; otherwise
  contributes neither (an identifier scheme this tool has no matcher for -- not an error, the same
  "unsupported, not broken" treatment `github_advisory.clj/supported-entry` already gives an
  unrecognized purl type).
- `map-statement [statement]` -- OpenVEX statement -> canonical `domain.vex` statement, or nil when
  `vulnerability.name` or `status` don't resolve to something usable (mirrors `map-advisory`'s
  nil-on-unusable-id style in both existing vulnerability adapters). Snake_case OpenVEX values
  (`not_affected`, `vulnerable_code_not_present`, ...) are translated to the domain's kebab-case
  keywords via small private lookup tables; an unrecognized `status` drops the whole statement
  (nothing usable to report).
- `read-vex-statements [path]` -- **nil when `path` is nil** (no VEX configured is the default,
  silent, not a warning); otherwise globs `path`, warns on `*err*` if zero `*.vex.json` files are
  found there (opted in but found nothing -- mirrors the existing "no `*.cdx.json` files found"
  warning), and returns the flattened, mapped statements across every file found.

### Repository wiring (`sbom-tool.application.repository`)

- `vex-statements` accessor: `(:vex-statements @state)`.
- **No new multimethod.** `initialize-state` calls `(openvex/read-vex-statements (:vex-path
  options))` directly and stores the result -- the same plain-function shape
  `adapter/license/spdx.clj/read-license-list` already uses for an optional, single-format
  external resource with no bundled-default fallback (`--spdx-license-list` is the closest
  existing precedent, not `--vulnerability-source`'s multimethod dispatch, since that dispatch
  exists specifically to let *several* interchangeable adapters share one CLI option -- there is
  only one VEX format in scope here, and adding dispatch for a hypothetical second one would be
  speculative generality this project's own adapter plans have consistently avoided elsewhere).

### Domain merge (`sbom-tool.domain.vulnerability`)

- The private `vulnerability-entries` helper gains two optional trailing args, `vex-statements` and
  `component` (both nil-safe; omitting them keeps today's exact behavior -- the same
  optional-arg-with-a-safe-default pattern `consolidated-component-vulnerabilities` already
  established for `external-vulnerabilities`). For each vulnerability it resolves `(vex/vex-entry
  vex-statements component id)`; when that entry is `vex/exempted?`, the report entry's `:status`
  becomes the VEX status (`:not-affected`/`:fixed`) instead of the policy-computed one -- VEX
  exemption is authoritative over policy `:blocked`/`:ok`, the same way a policy's own `:ignored`
  exemption already overrides `:max-severity` gating today. The entry also carries a `:vex` key
  (`{:status :justification :notes}`) whenever *any* statement matched, including a
  non-exempting `:affected`/`:under-investigation` one (shown as an annotation, gating unchanged).
- `consolidated-component-report` gains a matching optional 4th arg (`vex-statements`), threaded
  into `vulnerability-entries` alongside `component` (already in scope there). The single-document
  `component-report` variant -- used only by tests today, never by the application layer -- is
  left at its current 3-arity; nothing needs VEX there.

### Application layer (`sbom-tool.application.report`)

- `vulnerabilities-by-component` fetches `repo/vex-statements` alongside the existing
  `repo/external-vulnerabilities` and threads it into `consolidated-component-report`, mirroring
  exactly how it already threads `external-vulnerabilities`.
- `blocked-vulnerabilities` becomes VEX-aware **without** needing per-document purl resolution: a
  new private `vex-exempted-ids` groups `vulnerabilities-by-component`'s per-component
  vulnerability entries by `:id`, and returns the ids where **every** entry for that id (i.e.
  every consolidated component the vulnerability affects) is `vex/exempted?`. `blocked-
  vulnerabilities` removes those fully-exempted ids from `(repo/vulnerabilities)` before applying
  its existing `vulnerability-status` filter. A vulnerability exempted for only *some* of the
  components it affects stays blocked -- correctly, since it is still a real risk to the
  un-exempted ones. This also means `--fail-on-violations` (via `cli/violations?`, unchanged
  itself) picks up VEX exemptions for free, since it already calls `blocked-vulnerabilities`.

### CLI (`sbom-tool.adapter.ui.cli`)

- New option: `-X, --vex-path PATH` -- "Path of a folder containing OpenVEX documents
  (*.vex.json) to apply to vulnerability reports -- optional, no VEX is applied unless given."
- `initialize-state` gains the `read-vex-statements` call described above.
- `(:require [sbom-tool.adapter.vex.openvex :as openvex-repo])`.

### Report rendering (`sbom-tool.adapter.report.markdown`)

- Extend `vulnerability-status-label` with `:not-affected`/`:fixed` labels (e.g. `"not affected
  (VEX)"`/`"fixed (VEX)"`).
- Extend `format-vulnerability-entry` to append the VEX justification when present, e.g.
  `"CVE-2023-1234 (high, not affected (VEX): vulnerable-code-not-present)"` -- folds into the
  existing single-cell vulnerability string, no table-shape change (severity/status already work
  this way).
- JSON (`adapter/report/json.clj`): no change -- it's a generic passthrough, and the new
  `:vex`/extended `:status` values serialize automatically.

## Step-by-step implementation

### Step 1 -- New domain namespace

`src/sbom_tool/domain/vex.clj`: specs for the canonical statement shape; `matching-statements`,
`vex-entry` (with the conservative-precedence resolution), `exempted?`, as designed above.

### Step 2 -- New adapter namespace

`src/sbom_tool/adapter/vex/openvex.clj`: `vex-files`, `read-vex-document`, `product-identifiers`,
`map-statement`, `read-vex-statements`, as designed above.

### Step 3 -- Repository wiring

`src/sbom_tool/application/repository.clj`: `vex-statements` accessor (`(:vex-statements
@state)`). No multimethod (see Design).

### Step 4 -- Domain merge

`src/sbom_tool/domain/vulnerability.clj`: `vulnerability-entries` gains optional `vex-statements`/
`component` args; `consolidated-component-report` gains a matching optional 4th arg, threaded
through alongside the `component` it already has in scope.

### Step 5 -- Application layer

`src/sbom_tool/application/report.clj`: `vulnerabilities-by-component` threads `repo/vex-
statements` through; new private `vex-exempted-ids`; `blocked-vulnerabilities` filters through it
before its existing `vulnerability-status` check.

### Step 6 -- CLI

`src/sbom_tool/adapter/ui/cli.clj`: `-X/--vex-path` option; require the new adapter namespace;
wire `initialize-state`.

### Step 7 -- Report rendering

`src/sbom_tool/adapter/report/markdown.clj`: new status labels; VEX justification appended in
`format-vulnerability-entry`.

### Step 8 -- Tests

- New `test/sbom_tool/domain/vex_test.clj`: matching by purl, by cpe, by alias, case-insensitively;
  precedence when statements conflict (`:affected` beats `:not-affected`, `:under-investigation`
  beats `:fixed`); `exempted?` for all four statuses; no match when purl/cpe/id don't line up.
- New `test/sbom_tool/adapter/vex/openvex_test.clj` + `test/resources/openvex/*.vex.json`
  fixtures: a product identified via `@id` as a bare purl, a product via `identifiers.purl`, a
  product via `identifiers.cpe23`, a statement with an unrecognized `status` (dropped), a
  malformed-JSON fixture (exercises `:malformed-vex-json`), and a directory with zero `*.vex.json`
  files (exercises the warning path).
- Extend `test/sbom_tool/domain/vulnerability_test.clj`: a `not_affected` statement downgrades an
  otherwise-`:blocked` entry to `:not-affected`; a `fixed` statement likewise; an `:affected`
  statement leaves policy status untouched but still attaches `:vex`; conflicting statements
  resolve to the conservative one; a component the statement doesn't name is unaffected.
- Extend `test/sbom_tool/application/report_test.clj`: `vulnerabilities-by-component` picks up
  `repo/vex-statements`; `blocked-vulnerabilities` excludes an id VEX-exempted on every component
  it affects, but keeps one exempted on only some of them.
- Extend `test/sbom_tool/adapter/ui/cli_test.clj`'s `base-options` fixture with `:vex-path nil`.
- The real end-to-end flow (CLI flag through to markdown/JSON output) is exercised via `bb test`
  like everything else in this suite -- no network involved anywhere in this feature, so nothing
  needs to be pushed to manual-only verification the way the live-network adapters' fetch calls
  are.

### Step 9 -- Documentation

Update `README.md`: document `-X/--vex-path` in the options table; add a short "VEX (OpenVEX)"
section next to the existing vulnerability-source ones, explaining the opt-in nature, the
exemption semantics (`not_affected`/`fixed` suppress blocking, `affected`/`under_investigation`
annotate only), and the conservative-wins conflict rule; note in the existing vulnerability
disclaimer that VEX suppresses only what a matching statement actually names, not a component's
vulnerabilities in general.

## File-by-file summary

| File | Change |
|---|---|
| `src/sbom_tool/domain/vex.clj` | **new** -- statement spec, `matching-statements`, `vex-entry`, `exempted?` |
| `src/sbom_tool/adapter/vex/openvex.clj` | **new** -- directory read, JSON parsing, statement mapping, `read-vex-statements` |
| `src/sbom_tool/application/repository.clj` | `vex-statements` accessor |
| `src/sbom_tool/domain/vulnerability.clj` | `vulnerability-entries`/`consolidated-component-report` gain optional `vex-statements`(+`component`) args |
| `src/sbom_tool/application/report.clj` | `vulnerabilities-by-component` threads `repo/vex-statements`; `blocked-vulnerabilities` gains `vex-exempted-ids` filtering |
| `src/sbom_tool/adapter/ui/cli.clj` | `-X/--vex-path` option; wired into `initialize-state` |
| `src/sbom_tool/adapter/report/markdown.clj` | new VEX status labels; justification in `format-vulnerability-entry` |
| `test/sbom_tool/domain/vex_test.clj` | **new** |
| `test/sbom_tool/adapter/vex/openvex_test.clj` | **new** |
| `test/resources/openvex/*.vex.json` | **new** fixtures |
| `test/sbom_tool/domain/vulnerability_test.clj`, `test/sbom_tool/application/report_test.clj`, `test/sbom_tool/adapter/ui/cli_test.clj` | extended |
| `README.md` | new option, new section, extended disclaimer |

## Verification

- `bb test` -- all new/existing tests green, no network access required anywhere in this feature.
- Manual: a small SBOM with one known-vulnerable component plus an OpenVEX document asserting
  `not_affected` for that component's purl -- confirm `-r vulnerabilities -o markdown` labels it
  "not affected (VEX)" with its justification, and that `-r blocked-vulnerabilities
  --fail-on-violations` no longer exits 1 for it (assuming it was the only violation).
- Manual: two OpenVEX documents under the same `--vex-path` disagreeing on the same
  vulnerability+product (`not_affected` vs. `affected`) -- confirm the component report shows
  `:affected` (conservative) and the vulnerability remains blocked.
- Manual: a vulnerability affecting two components, VEX-exempted for only one of them -- confirm
  it still appears in `blocked-vulnerabilities` and still fails `--fail-on-violations`.

## Risks / open questions

- **Purl/cpe-only product matching**: an OpenVEX document that identifies products only by an
  `@id`/identifier scheme this tool can't recognize (e.g. a SWID tag) won't match any component --
  the same category of capability boundary the existing vulnerability adapters already accept for
  purl-less components.
- **Conflict precedence is a judgment call**: "most conservative status wins" was chosen over,
  e.g., "most recent statement timestamp wins," for simplicity and safety; OpenVEX's own spec
  doesn't mandate either resolution strategy. Worth revisiting if real-world multi-supplier VEX
  conflicts prove this too coarse (e.g. a supplier's later, corrected `not_affected` statement
  never being able to override an older `affected` one from a different, stale source).
- **`blocked-vulnerabilities`'s indirect VEX-awareness** (via `vulnerabilities-by-component`, not a
  direct per-document id-to-purl resolution) means a vulnerability with zero consolidated
  components recorded against it (shouldn't occur with real data) would never be exempted -- an
  acceptably conservative failure mode, not a correctness gap in practice.

## Follow-ups (explicitly out of scope here)

- CSAF VEX (or any second VEX format) as a `--vex-format`-style dispatch, if/when actually needed.
- `products[].subcomponents` matching.
- A direct, per-SBOM-document id-to-purl resolution so `blocked-vulnerabilities` no longer needs
  the "exempted on every affected component" indirection.
- Surfacing VEX document-level metadata (author, timestamp) in reports.
