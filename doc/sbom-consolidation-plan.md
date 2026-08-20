# Plan: Consolidated Multi-Format SBOM Ingestion

**Status:** all 7 rollout phases implemented, including the §5 decisions (opt-in
`--merge-unidentified` flag, `:conflicts` tracking, blank/`NOASSERTION` guarding, `:sources`
exposed in reports). `application/report.clj`'s component-based reports and the CLI's `-s`
default now run on the consolidated, multi-format view described below.

## 1. Feasibility

Yes. The canonical domain model (`domain/sbom.clj`) is already format-agnostic: `::format`
(`:cyclonedx`/`:spdx`) lives on a *document's* `::bom-metadata`, not on individual components, and
`::component` carries `::identifiers` (`::purl`, `::cpe`, `::bom-ref`, `::spdx-id`) that are
already populated by both `adapter/cdx/file_repository.clj` and `adapter/spdx/file_repository.clj`.
Nothing in the domain model needs to change to support ingesting both formats at once.

What currently prevents it, all in the application/CLI layer, not the domain:

1. `application/repository.clj`'s `read-sboms` multimethod dispatches on a single
   `:sbom-format` option, and both `defmethod repo/read-sboms :cdx`/`:spdx` do
   `(swap! repo/state assoc :sboms ...)` — an `assoc`, not a merge. Calling it a second time for
   the other format overwrites the first call's SBOMs instead of adding to them.
2. `adapter/ui/cli.clj`'s `-s/--sbom-format` only ever produces one keyword (`:cdx` or `:spdx`),
   so there is no way today to ask for both.
3. Even with both loaded side by side, nothing merges them: `repo/components` flattens every
   SBOM's components into a `set`, which only dedupes components that are byte-for-byte identical
   maps — the same library described by a CycloneDX file (with vulnerability data) and an SPDX
   file (with `concluded`/`from-files` license detail) would show up as two separate components,
   not one consolidated view. `repo/sbom-components` intentionally keeps `[sbom component]` pairs
   scoped per document, because `::affected` vulnerability ids are only unique within the
   document that declares them (see `doc/reports-plan.md` §3.2) — any merge has to preserve that
   scoping rather than lose it.

## 2. Goal

Point the tool at a folder containing a mix of `*.cdx.json` and `*.spdx.json` files and get back
one consolidated component per real-world package, with the union of whatever each source
document contributes to it (e.g. CycloneDX-reported vulnerabilities together with SPDX's more
detailed `concluded`/`from-files` license analysis for the same library), instead of one
disjoint report per format.

## 3. Design

### 3.1 Reading both formats in one run

- `adapter/cdx/file_repository.clj` and `adapter/spdx/file_repository.clj` stay as they are —
  each still maps its own file glob to canonical `::sbom` documents.
- `application/repository.clj`:
  - Change the `:cdx`/`:spdx` `read-sboms` methods to accumulate rather than replace:
    `(swap! repo/state update :sboms (fnil into []) new-sboms)`.
  - Add a new `sbom-format` value, `:auto` (proposed new CLI default), meaning "read every
    `*.cdx.json` and `*.spdx.json` file under the path": its `read-sboms` method simply
    delegates to both existing methods in turn.
- `adapter/ui/cli.clj`: `-s/--sbom-format` default changes from `:cdx` to `:auto`; `:cdx`/`:spdx`
  remain available to restrict ingestion to one format (e.g. to ignore stray files of the other
  kind in the same folder).
- This alone (phase 1 below) makes both formats loadable together — it does not yet merge
  anything; `report/licenses` etc. would just show every component from every document,
  duplicated wherever the same package is described twice.

### 3.2 Component identity across documents (new domain logic)

To recognize "this CycloneDX component and this SPDX package are the same real thing", add a
`component-identity` function (`domain/sbom.clj`, or a new `domain/component.clj` if it grows):

```clojure
(defn component-identity [component]
  (or (get-in component [::identifiers ::purl])
      (get-in component [::identifiers ::cpe])
      [(::name component) (::version component)]))
```

- `::purl` is the strongest signal (stable, ecosystem-qualified) and is populated by both
  adapters when present in the source document.
- `::cpe` is the next best (CycloneDX only, currently).
- `[name version]` is the fallback both formats always have, but is a heuristic, not a
  guarantee — see §5.

### 3.3 Merging component data (pure domain logic)

Add `merge-components [components]` (`domain/sbom.clj`) that folds a seq of `::component`s
sharing one identity into a single one:

- Scalar fields (`::name`, `::version`, `::description`, `::copyright`, `::supplier`,
  `::manufacturer`, `::component-type`): first non-nil wins, in read order; `::component-type`
  additionally prefers any specific type over `:other`.
- Collection fields (`::hashes`, `::external-references`): concatenated and deduplicated.
- `::identifiers`: merged map, union of keys, first non-nil value per key.
- `::licenses`: `::declared`/`::concluded`/`::from-files` vectors merged per key, concatenated
  and deduplicated — this is precisely the "CycloneDX vulnerability data + SPDX license detail"
  combination motivating this plan, since CycloneDX only ever reports `::declared` licenses
  while SPDX's `::concluded`/`::from-files` carry deeper analysis.
- `::properties`: merged map, later document wins on key collision.
- Result also carries a new `::origins` field: a vector of `{::sbom-id ... ::component-id ...}`
  pairs, one per source document, recording which document contributed which local component id
  — needed to resolve vulnerabilities back to the right document (§3.4).

### 3.4 Repository: consolidated components + vulnerability resolution

- `application/repository.clj` gains `consolidated-components []`: groups `sbom-components`
  pairs by `component-identity`, runs each group through `merge-components`, and returns one
  merged component per identity.
- Vulnerability resolution changes from "one `[sbom component]` pair" to "one merged component
  with several origins": for each origin, look up that origin's own document and resolve
  `::affected` against the origin's local component id (exactly as `vulnerability/component-
  -vulnerabilities` does today), then union the results across origins, deduplicating by
  vulnerability id (the same CVE can legitimately appear in more than one source document for
  the same package).
- `repo/components` and `repo/sbom-components` are unchanged and kept as the lower-level,
  per-document accessors — `consolidated-components` is built on top of them, not a replacement.

### 3.5 Reports

- `application/report.clj`'s component-based reports (`licenses`, `vulnerabilities-by-component`,
  `blacklisted-licenses`, etc.) switch from `repo/components`/`repo/sbom-components` to
  `repo/consolidated-components`, so a package described in both a CDX and an SPDX file is
  reported once, carrying the union of both documents' knowledge.
- Report shapes (the maps/vectors returned) do not need to change — only which components feed
  them — so downstream consumers (markdown/JSON renderers, `--fail-on-violations`) are
  unaffected.

### 3.6 CLI / docs

- `-s/--sbom-format` default becomes `:auto`; `:cdx`/`:spdx` remain as explicit overrides.
- README's format/option documentation updated to describe mixed-format folders and the new
  default.

## 4. Rollout phases

1. **Repository plumbing** (done): accumulate instead of replace in `read-sboms`
   (`application/repository.clj`, `adapter/cdx/file_repository.clj`,
   `adapter/spdx/file_repository.clj`), add the `:auto` dispatch delegating to both formats.
   No behavior change for single-format callers. Tested in
   `test/sbom_tool/application/repository_test.clj` against a mixed-format fixture folder
   (`test/resources/sboms/sample.cdx.json` + `sample.spdx.json`). The CLI default is unchanged
   for now (`-s` still defaults to `:cdx`) — that flip is phase 6.
2. **Domain** (done): `component-identity` + `merge-components` added in the new
   `domain/component.clj`, unit tested in `test/sbom_tool/domain/component_test.clj` against
   synthetic components covering the purl/cpe/name+version fallback chain and each field's merge
   rule (scalar first-non-nil, `::component-type` specific-over-`:other`, deduplicated
   `::hashes`/`::external-references`, key-wise `::identifiers`/`::licenses`/`::properties`
   merging).
3. **Repository** (done): `repo/consolidated-components` groups `sbom-components` by
   `component/component-identity`, runs each group through `component/merge-components`, and
   attaches an `:origins` vector (`{:sbom sbom :component-id id}` per source document) --
   simpler than the `{::sbom-id ... ::component-id ...}` shape originally sketched in §3.3,
   since carrying the actual origin `sbom` value avoids needing a separate id-based lookup table
   (SBOM documents don't always have a usable id of their own). The `test/resources/sboms/`
   fixtures now include a `shared-lib` package described by both documents (matched by purl,
   with the CycloneDX side contributing a vulnerability and a declared license, and the SPDX
   side contributing concluded/from-files license detail) alongside `foo` (CycloneDX-only) and
   `bar` (SPDX-only), tested in `test/sbom_tool/application/repository_test.clj`.
4. **Vulnerability resolution across origins** (done): `domain/vulnerability.clj` gained
   `consolidated-component-vulnerabilities` (resolves each origin against its own document,
   dedupes by `::sbom/id`) and `consolidated-component-report` (mirrors `component-report` for a
   merged component). Tested in `test/sbom_tool/domain/vulnerability_test.clj` with a synthetic
   merged component whose CVE is reported by both origins (deduplicated to one) and one CVE
   reported by only one origin, plus end-to-end against the real `shared-lib` fixture in
   `repository_test.clj`, whose CVE is only ever reported by the CycloneDX-side origin.
5. **Wire `application/report.clj`** (done): `licenses`, `multi-licensed`, `unidentified-
   licenses` and `vulnerabilities-by-component` (the latter via the new `vulnerability/
   consolidated-component-report`) now run on `repo/consolidated-components` instead of
   `repo/components`/`repo/sbom-components`; `blacklisted-licenses` inherits this through
   `licenses`. `vulnerability-summary`/`blocked-vulnerabilities` stay document/severity-based,
   per §3.5, so are unchanged. Every entry gains `:sources` (via the new `domain/component/
   origin-sources`) and, when present, `:conflicts`, added by a small `with-provenance` helper
   rather than threading them through each domain report function. The `markdown` adapter
   renders `:sources` as a table column on the four affected reports; `:conflicts` is only
   surfaced in `edn`/`json` output, to keep the tables readable.
6. **CLI** (done): `-s/--sbom-format` default is now `:auto`; `:cdx`/`:spdx` remain as explicit
   overrides. Added `-m/--merge-unidentified`, wired into `repo/state`'s `:merge-unidentified?`
   at `initialize-state` time, implementing the §5 opt-in decision. README updated.
7. **End-to-end fixture test** (done): `test/sbom_tool/application/report_test.clj`'s
   `consolidated-reports-e2e-test` reads the mixed `test/resources/sboms/` fixture folder via
   `repo/read-sboms {:sbom-format :auto} ...` and asserts, through `report/licenses` and
   `report/vulnerabilities-by-component`, a single `"shared-lib"` row carrying both documents'
   license data and a `:sources` of `#{:cyclonedx :spdx}`, plus its CVE resolving correctly.

## 5. Open decisions

- The `[name version]` fallback identity is a heuristic: two unrelated packages that happen to
  share a name and version (plausible across ecosystems, e.g. a Python and an npm package both
  called `requests`) would be wrongly merged. Should that fallback be opt-in (e.g. a CLI flag),
  or should components without a `purl`/`cpe` simply never be merged, at the cost of not
  consolidating them at all?
  - **Decision**: make the merge opt in per CLI flag.
  - **Implemented**: `component/component-identity` takes a `merge-unidentified?` flag (default
    `false`); without it, a component lacking a `purl`/`cpe` uses itself as its own identity, so
    it only ever "matches" byte-for-byte identical data, never another document's differing
    description of the same package. `repo/consolidated-components` reads the flag from
    `repo/state`'s `:merge-unidentified?`, set by the CLI's new `-m/--merge-unidentified`.
- Merge precedence for genuinely conflicting scalar values (e.g. two different `::description`
  texts, or a different `::supplier` per document) is currently "first document wins, rest
  silently dropped". Should conflicts instead be surfaced somewhere (e.g. logged, or listed in
  `::origins`) so a reviewer can tell the data disagreed?
  - **Decision**: conflicts should be listed in `::origins`, then we we can report on them.
    Empty values should never override non-empty values and a value of 'NOASSERTION' should also not override valid information.
  - **Implemented**: `component/merge-components` computes `:conflicts` -- a map of field key
    to the distinct non-blank values found across the source components, for every scalar field
    where more than one exists -- and attaches it as a sibling of `:origins` on the merged
    result (rather than nesting per-origin values inside `:origins` itself, which would have
    meant carrying full raw component data there just for the rare disagreement case). A private
    `blank-value?` (nil, blank string, case-insensitive `NOASSERTION`, or `:other` for
    `::component-type`) backs both this and `first-value`'s merge, so a blank/`NOASSERTION` value
    never overrides a real one regardless of read order.
- Should `::origins` be exposed in reports (e.g. a "sources" column listing which files
  contributed to a row), or stay purely internal to vulnerability resolution?
  - **Decision**: yes, expose the sources in the reports.
  - **Implemented**: `component/origin-sources` reduces `:origins` to the distinct source
    *document formats* (`:cyclonedx`/`:spdx`) rather than file paths -- the domain model does not
    track originating filenames, only each document's `::bom-metadata`, so "sources" means
    "which format(s)", not "which file(s)". `application/report.clj` attaches this as `:sources`
    on every component-based report entry; the `markdown` adapter renders it as a table column.
- This mirrors, at the component level, the same "merge across documents" question already open
  for licenses in `doc/reports-plan.md` §5 — worth resolving both together rather than
  independently.
