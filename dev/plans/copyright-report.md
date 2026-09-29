# Plan: Copyright Report

**Status:** implemented
**Date:** 2026-09-29
**Related:** [report.clj](../src/sbom_tool/application/report.clj) (`licenses`), [dev/plans/proprietary-components.md](proprietary-components.md)

Add a `copyright` report, analogous to the existing `licenses` report, that
lists every consolidated component's copyright notice. Bundled into the
`:all-license` set of reports alongside the license reports.

## Problem

`::sbom/copyright` is already part of the canonical component model
([sbom.clj:106](../src/sbom_tool/domain/sbom.clj#L106)), populated by both
adapters (CycloneDX's `copyright` field,
[cdx.clj:179](../src/sbom_tool/adapter/sbom/cdx.clj#L179); SPDX's
`copyrightText`, [spdx.clj:200](../src/sbom_tool/adapter/sbom/spdx.clj#L200)),
and carried through consolidation by `merge-components` (first non-blank
value wins, conflicts recorded, see
[component.clj:105-130](../src/sbom_tool/domain/component.clj#L105-L130)).
Nothing in `application.report` or the CLI/renderers ever surfaces it,
though -- there is no way to list which copyright notice(s) the tool
resolved per component, or to spot components that carry none at all.

## Design

Unlike license, copyright has no policy dimension (no whitelist/blacklist,
no SPDX identifier resolution) -- `::sbom/copyright` is already a single
merged, free-text string per component. This makes the report much simpler
than `licenses`: no new domain namespace, no `policies` argument, just a
straight per-component projection, following the same shape and provenance
convention as every other component-based report
(`with-provenance`/`:sources`/`:conflicts`, see
[report.clj:8-15](../src/sbom_tool/application/report.clj#L8-L15)).

### `sbom_tool.application.report/copyright`

```clojure
(defn copyright
  "Returns the copyright report for all consolidated components: each
   entry's id, name, version and type, plus its resolved copyright notice
   (nil if no source document asserted one), `:sources` and, when the
   source documents disagreed, `:conflicts`."
  []
  (mapv (fn [component]
          (with-provenance component
            {:id (::sbom/id component)
             :name (::sbom/name component)
             :version (::sbom/version component)
             :component-type (::sbom/component-type component)
             :copyright (::sbom/copyright component)}))
        (repo/consolidated-components)))
```

Every consolidated component gets exactly one row (no fan-out, unlike
`licenses`, since there is only ever one resolved copyright value per
component) -- including components with a nil `:copyright`, so the report
stays a complete inventory rather than silently dropping components with no
notice.

### `sbom_tool.application.report/missing-copyright`

A second report, analogous to `unidentified-licenses`/`blacklisted-licenses`
reusing `licenses`: the subset of `copyright` entries with no resolved
notice, for quickly spotting components that need one added or investigated.

```clojure
(defn missing-copyright
  "Returns the copyright report entries (see `copyright`) for components
   that have no copyright notice asserted by any source document."
  []
  (filterv (comp nil? :copyright) (copyright)))
```

### CLI wiring (`sbom_tool.adapter.ui.cli`)

- Add `:copyright report/copyright` and `:missing-copyright
  report/missing-copyright` to the `reports` map
  ([cli.clj:46-63](../src/sbom_tool/adapter/ui/cli.clj#L46-L63)), so both are
  selectable via `--report copyright` / `--report missing-copyright`.
- Add both to `all-license-reports`
  ([cli.clj:25-33](../src/sbom_tool/adapter/ui/cli.clj#L25-L33)), so they are
  included by default (`--report all-license`, the CLI's default) and by
  `--report all`. This is a deliberate contrast with the vulnerability
  reports' opt-in bundling (`all-vulnerability-reports`'s doc comment,
  [cli.clj:35-40](../src/sbom_tool/adapter/ui/cli.clj#L35-L40)): copyright,
  like license, is present in essentially every real SBOM, so reporting an
  empty `missing-copyright` reads as "checked, none missing" rather than
  "nothing to say" -- the same reasoning that keeps `unidentified-licenses`
  bundled by default.

### Rendering

**Markdown** (`sbom_tool.adapter.report.markdown`):

```clojure
(defn- render-copyright
  [data]
  (md-table ["Component" "Version" "Type" "Copyright" "Sources"]
            (for [entry data]
              [(:name entry) (:version entry)
               (some-> (:component-type entry) name)
               (:copyright entry)
               (format-sources (:sources entry))])))
```

- `report-headings`: add `:copyright "Copyright"` and `:missing-copyright
  "Missing Copyright"`.
- `report-renderers`: add `:copyright render-copyright` and
  `:missing-copyright render-copyright` (reusing the same renderer, same
  pattern as `:blacklisted-licenses render-licenses`).

**JSON** (`sbom_tool.adapter.report.json`): no change -- it serializes
report data generically regardless of `report-key`.

### Documentation

- [README.md](../README.md): mention `copyright`/`missing-copyright` in the
  report list, and add both to the component-based reports enumerated in the
  "Multi-format consolidation" paragraph
  ([README.md:191-192](../README.md#L191)) that carry `:sources`/`:conflicts`.
- [AGENTS.md](../AGENTS.md): optionally add a bullet under "SBOM Tool
  reports on licenses and vulnerabilities" noting copyright is reported too
  -- low priority, not required for correctness.

## Touch points

| File | Change |
|---|---|
| [src/sbom_tool/application/report.clj](../src/sbom_tool/application/report.clj) | New `copyright` and `missing-copyright` functions |
| [src/sbom_tool/adapter/ui/cli.clj](../src/sbom_tool/adapter/ui/cli.clj) | Register both in `reports` and in `all-license-reports` |
| [src/sbom_tool/adapter/report/markdown.clj](../src/sbom_tool/adapter/report/markdown.clj) | `render-copyright`; entries in `report-headings`/`report-renderers` |
| [README.md](../README.md) | Document the new reports and extend the `:sources`/`:conflicts` report list |
| test/sbom_tool/application/report_test.clj | `copyright`: one row per consolidated component including a nil-copyright one; `:sources`/`:conflicts` provenance on a merged component with disagreeing copyright text; `missing-copyright`: only nil-copyright entries |
| test/sbom_tool/adapter/report/markdown_test.clj | `render-copyright`: renders the Copyright/Sources columns; a nil `:copyright` renders as a blank cell |
| test/sbom_tool/adapter/ui/cli_test.clj | `--report copyright` / `--report missing-copyright` run without error; `:all-license`/`:all` bundles include both keys |

## Decisions

- **No new domain namespace.** `license.clj` earns its size from policy
  matching, SPDX name/URL resolution and license-expression parsing; none of
  that applies to a single free-text field, so `copyright`/
  `missing-copyright` live directly in `application.report`, consistent with
  how other simple, policy-free projections are handled there.
- **Bundled into `:all-license`, not a separate `--report` category.**
  Copyright is a license-adjacent compliance concern (attribution
  requirements typically travel with license obligations), and reusing the
  existing bundle avoids a third `all-*`/CLI-flag concept for a single pair
  of reports.
- **One row per component, not fan-out per notice.** `::sbom/copyright` is
  already merged to a single string by `merge-components`; unlike
  `licenses` (which fans out over a genuine collection), there is nothing to
  fan out over here. Disagreement across source documents is fully captured
  by the existing generic `:conflicts` mechanism, not a per-report concept.
- **`missing-copyright` flags absence only, no severity/policy status.**
  There is no whitelist/blacklist analog for copyright text, so unlike
  `unidentified-licenses` there is only one "needs attention" reason; no
  `:reason` key is needed, just the same entry shape as `copyright` filtered
  down.
