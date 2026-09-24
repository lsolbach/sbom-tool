# Plan: Proprietary and Reviewed Components in the License Policy

**Status:** implemented
**Date:** 2026-09-24
**Related:** [dev/ideas.md](../ideas.md) (License Policy)

Implementation plan for [dev/ideas.md](ideas.md)'s "List Proprietary Components"
idea, extended to cover a second, analogous case raised during planning: let
a license policy also declare specific components as already manually
reviewed. Both features let the policy attach a fixed, human-supplied fact
about a specific component that overrides what the tool would otherwise
report:

- **`:proprietary`** -- this component is closed source; its total absence
  of license metadata is expected, not a data gap.
- **`:reviewed`** -- a person already looked at this component's ambiguous
  or unresolved license situation and accepted it; stop flagging it as
  needing attention.

## Problem

`report/unidentified-licenses` (see
[report.clj:87-119](../src/sbom_tool/application/report.clj#L87-L119)) lists
every consolidated component that has no license metadata at all
(`:reason :no-license`) or whose license text/id can't be resolved to a
standard SPDX identifier (`:reason :unidentified-license`). Internally
built, closed-source components legitimately carry no license metadata --
there is nothing to resolve -- but they currently show up indistinguishable
from a genuine SBOM data gap. There is no way to tell the tool "this
component is known to be proprietary, stop flagging it as missing license
data."

Separately, licenses that are neither whitelisted nor blacklisted are
reported as `:grey` -- per the existing policy file's own comment (see
[example-license-policy.edn:9-10](../example-license-policy.edn#L9-L10)),
grey "requires manual review". Once that manual review has actually
happened and the license was accepted, the component keeps showing up as
`:grey` ("still needs review") indefinitely, with no way to record that the
review already took place -- the same class of problem as proprietary
components, just for a different bucket (grey licenses / unresolved license
text, rather than missing license metadata).

## Design

### Policy shape

Add two optional keys to the license policy EDN, siblings of the existing
`:default`/`:library`/... usage-bucket keys (see
[example-license-policy.edn](../example-license-policy.edn)): `:proprietary`
and `:reviewed`. Both use the same matcher shape:

```clojure
{:default {:whitelist #{...} :blacklist #{...}}
 :library {:whitelist #{...} :blacklist #{...}}

 ;; Components known to be proprietary/closed source: reported with a
 ;; `proprietary` status instead of "no license" / "unidentified license".
 :proprietary #{"acme-internal-lib"
                {:name "acme-widget" :version "3.2.0"}
                {:purl "pkg:generic/acme/legacy-tool"}}

 ;; Components whose license situation has already been manually reviewed
 ;; and accepted: reported with a `reviewed` status instead of `grey` /
 ;; "unidentified license" / "no license".
 :reviewed #{"beerware-fork"
             {:name "vendor-sdk" :version "9.1.0"}}}
```

Each entry is either a bare string, shorthand for `{:name "..."}`, or a map:

- `{:purl "..."}` -- matches a component whose `::sbom/identifiers
  ::sbom/purl` equals it exactly. Highest-confidence match, for the rarer
  case where a proprietary/reviewed component is still resolved through an
  internal package registry.
- `{:name "..."}` -- matches any component with that `::sbom/name`,
  regardless of version. The common case: internal components typically
  have neither a purl nor a cpe.
- `{:name "..." :version "..."}` -- matches only that exact version.

**Why a global set rather than per-usage-bucket:** `:whitelist`/`:blacklist`
are intentionally scoped per component type because the *same license* can
be acceptable for one usage and not another (see the comment in
[example-license-policy.edn:42-50](../example-license-policy.edn#L42-L50)).
Whether *a specific named component* is proprietary or already reviewed is
not usage-dependent, and `policy-for` fully replaces `:default` with a
matching type's bucket (no merging, see
[license.clj:39-43](../src/sbom_tool/domain/license.clj#L39-L43)) -- so a
per-bucket set would force every bucket to redeclare it or silently lose
entries for components resolved to a non-`:default` bucket. A single
top-level set per concern avoids that trap entirely.

**Why reuse the license policy file rather than a third/fourth policy
file/CLI flag:** vulnerability policy already gets its own file, flag and
repository slot (`--vulnerability-policy`, `read-vulnerability-policies`,
`repo/vulnerability-policies`) because it is a genuinely separate concern.
Proprietary and reviewed status are both part of license classification and
are only ever consulted alongside the license policy's own
`:default`/`:library` buckets, in the exact same functions
(`component-report`, `unidentified-licenses`). Piggybacking on the existing
`--license-policy` file and the `policies` map already threaded everywhere
avoids extra CLI flags, extra `repo/state` keys and extra read/validate
multimethods for two small sets.

**Scope decision for `:reviewed` -- what it overrides:** `:reviewed`
downgrades a component's otherwise-flagged status to `:reviewed` wherever
that status would be `:grey` (an identified license that's neither
whitelisted nor blacklisted), `:unidentified-license` (license text/id that
couldn't be resolved to a standard SPDX id) or `:no-license` (no license
metadata at all, unless `:proprietary` already explains it). It never
overrides `:white` (nothing to override) or `:black` (blacklisted licenses
stay hard-blocked -- a manual "accept anyway" for a blacklisted license is a
bigger policy exception than this mechanism is meant for, and isn't
requested by the idea; it would need its own explicit review-with-reason
mechanism if ever needed). If a component matches both `:proprietary` and
`:reviewed`, `:proprietary` wins for the no-license case since it's the
more specific explanation -- see "Matching" below, this falls out of the
implementation without extra branching.

### Spec (`sbom_tool.domain.license`)

```clojure
(s/def ::component-matcher
  (s/or :name ::sbom/non-empty-string
        :matcher (s/keys :req-un [::sbom/name] :opt-un [::sbom/version ::sbom/purl])))

(s/def ::component-matchers (s/coll-of ::component-matcher :kind set?))

(s/def ::proprietary ::component-matchers)
(s/def ::reviewed ::component-matchers)

(s/def ::type-policies (s/map-of ::policy-key ::type-policy))

;; ::policies can no longer be a plain `map-of` once :proprietary/:reviewed
;; are reserved keys with a different value shape than a `::type-policy`;
;; split validation into the reserved keys plus everything else.
(s/def ::policies
  (s/and map?
         #(s/valid? ::proprietary (get % :proprietary #{}))
         #(s/valid? ::reviewed (get % :reviewed #{}))
         #(s/valid? ::type-policies (apply dissoc % [:proprietary :reviewed]))))
```

`::sbom/purl` already exists as a spec in `sbom.clj` and is reused here.
This is backward compatible: existing policy files with neither key
validate exactly as before.

### Matching (`sbom_tool.domain.license`)

One shared matcher predicate, since `:proprietary` and `:reviewed` use the
identical matcher shape and matching rule; `proprietary?` and `reviewed?`
are thin, independently-callable wrappers over it (each still takes just
its own matcher set, not the whole `policies` map, consistent with e.g.
`policy-for`/`license-status` taking specific policy pieces rather than the
whole map):

```clojure
(defn- normalize-component-matcher
  [matcher]
  (if (string? matcher) {:name matcher} matcher))

(defn- matches-any?
  [matchers component]
  (boolean
   (some (fn [matcher]
           (let [{:keys [name version purl]} (normalize-component-matcher matcher)]
             (if purl
               (= purl (get-in component [::sbom/identifiers ::sbom/purl]))
               (and (= name (::sbom/name component))
                    (or (nil? version) (= version (::sbom/version component)))))))
         matchers)))

(defn proprietary?
  "Returns true if `component` matches any entry of `proprietary` (the
   policy's :proprietary set): an exact purl match, or else a name match,
   optionally narrowed to an exact version."
  [proprietary component]
  (matches-any? proprietary component))

(defn reviewed?
  "Returns true if `component` matches any entry of `reviewed` (the
   policy's :reviewed set), under the same matching rule as `proprietary?`."
  [reviewed component]
  (matches-any? reviewed component))
```

### Reporting (`sbom_tool.application.report/unidentified-licenses`)

Check `proprietary?` and `reviewed?` **first**, ahead of the existing
`empty?` / `not-any? spdx-identifiable?` checks, so a policy-declared
component is reported as such even if the SBOM happens to also carry stray
unresolved license text for it:

```clojure
(cond
  (license/proprietary? (:proprietary policies) component)
  (with-provenance component (assoc base :reason :proprietary))

  (license/reviewed? (:reviewed policies) component)
  (with-provenance component
    (cond-> (assoc base :reason :reviewed)
      (seq licenses) (assoc :licenses (into #{}
                                             (map (fn [lic]
                                                    (assoc (license/license-entry
                                                            policy spdx-licenses (license/license-identifier lic))
                                                           :url (license/license-url lic))))
                                             licenses))))

  (empty? licenses)
  (with-provenance component (assoc base :reason :no-license))

  (not-any? license/spdx-identifiable? licenses)
  (with-provenance component (assoc base :reason :unidentified-license :licenses ...)))
```

A `:reviewed` entry carries the same `:licenses` detail as an
`:unidentified-license` one when the component actually has license text
(so the report stays traceable to what was reviewed), and omits it when the
component genuinely has none (a reviewed no-license component).

A component that already resolves to a real whitelisted/blacklisted SPDX
license never reaches `unidentified-licenses` at all (it's not
"unidentified" regardless of the `:proprietary`/`:reviewed` sets) --
declaring it proprietary or reviewed in that case is inert, which is
acceptable.

### Closing the visibility gap in `licenses`/summary reports

**Decision:** a zero-license component must become visible in `licenses`,
`license-status-summary` and `license-summary` too, not just in
`unidentified-licenses` -- for the `:proprietary` case and the pre-existing
plain "no license" case (see [Decisions](#decisions) below). The same
reports must also reflect `:reviewed` overriding a `:grey` (or synthetic
`:no-license`) status, so a reviewed component stops appearing as "needs
review" everywhere, not just in `unidentified-licenses`.

Today, `component-report` (see
[license.clj:93-105](../src/sbom_tool/domain/license.clj#L93-L105)) gives a
zero-license component an empty `:licenses` vector, so it contributes
nothing to `(mapcat :licenses ...)`-based reports (`license-status-summary`,
`license-summary`) and renders as a blank row in `render-licenses`. Fix
this by having `component-report` synthesize a single license entry for
that case instead of an empty vector, carrying `:proprietary` when the
component matches the policy's `:proprietary` set or `:no-license`
otherwise; then, regardless of whether licenses were synthesized or real,
downgrade any `:grey`/`:no-license` status to `:reviewed` when the
component matches the policy's `:reviewed` set:

```clojure
(defn- reviewed-status
  [status]
  (if (#{:grey :no-license} status) :reviewed status))

(defn component-report
  [policies spdx-licenses component]
  (let [policy (policy-for policies (::sbom/component-type component))
        licenses (component-licenses component)
        raw-licenses (if (empty? licenses)
                       [{:license-id nil :license-name nil :license-url nil
                         :status (if (proprietary? (:proprietary policies) component)
                                   :proprietary
                                   :no-license)}]
                       (into []
                             (map (comp (partial license-entry policy spdx-licenses) license-identifier))
                             licenses))]
    {:id (::sbom/id component)
     :name (::sbom/name component)
     :version (::sbom/version component)
     :component-type (::sbom/component-type component)
     :licenses (if (reviewed? (:reviewed policies) component)
                 (mapv #(update % :status reviewed-status) raw-licenses)
                 raw-licenses)}))
```

`reviewed-status` never touches `:proprietary` (or `:white`/`:black`), so a
component that matches both `:proprietary` and `:reviewed` still ends up
`:proprietary` -- the more specific explanation -- without any extra
precedence logic. The synthetic entry (and `reviewed-status`) deliberately
bypasses `license-entry`/`license-status` (which only distinguish
`:white`/`:black`/`:grey` by identifier, and would return `:grey` for a nil
identifier -- indistinguishable from a genuinely unresolved license) so
"no license at all", "reviewed" and "grey, still needs review" stay visibly
different statuses.

Consequences elsewhere:

- `render-licenses`/`render-multi-licensed`'s status label map
  (`license-status-label` in
  [markdown.clj:32-33](../src/sbom_tool/adapter/report/markdown.clj#L32-L33))
  gains `:proprietary "proprietary"`, `:no-license "no license"` and
  `:reviewed "reviewed"`. `render-licenses`'s existing
  `(or (seq (:licenses entry)) [nil])` fallback for a component with zero
  licenses becomes unreachable through `component-report`-sourced data
  (there's always at least one synthetic entry now) but is harmless to
  leave in place as a defensive default.
- `license-status-summary` (a plain `frequencies` over `:status`, see
  [report.clj:61-68](../src/sbom_tool/application/report.clj#L61-L68))
  needs no code change -- it will now naturally start counting
  `:proprietary`, `:no-license` and `:reviewed` alongside
  `:white`/`:black`/`:grey`. `render-license-status-summary`'s hardcoded
  `[:white :grey :black]` column order (markdown.clj) must be extended to
  `[:white :grey :black :proprietary :no-license :reviewed]` so the new
  counts actually render.
- `license-summary` (counts components per `:license-id`, see
  [report.clj:70-77](../src/sbom_tool/application/report.clj#L70-L77))
  must switch from `map` to `keep` so the synthetic no-license/proprietary
  entries' `nil` `:license-id` doesn't pollute the per-license counts with
  a spurious `nil` bucket: `(keep :license-id)` instead of
  `(map :license-id)`. A reviewed component that has a real (grey)
  license id keeps counting under that id as before -- `reviewed-status`
  only changes `:status`, never `:license-id`.

### Rendering (`sbom_tool.adapter.report.markdown`)

Add `:proprietary` and `:reviewed` branches to
`render-unidentified-licenses`'s reason `case` (currently `:no-license` ->
`"no license"`, `:unidentified-license` -> `"unidentified license"`, see
[markdown.clj:136-139](../src/sbom_tool/adapter/report/markdown.clj#L136-L139)):

```clojure
(case (:reason entry)
  :no-license "no license"
  :unidentified-license "unidentified license"
  :proprietary "proprietary"
  :reviewed "reviewed"
  (name (:reason entry)))
```

JSON output needs no change -- `adapter.report.json` serializes report data
generically, so `:reason :proprietary`/`:reason :reviewed` just appear
as-is.

### Bundled default policy & example

Add documented (empty) `:proprietary #{}` and `:reviewed #{}` examples to
[example-license-policy.edn](../example-license-policy.edn) with a comment
explaining the matcher shapes and the difference in intent between the two.
Leave the bundled default (`resources/policy/license-policy.edn`) without
either key (or with empty sets) since it ships with no knowledge of any
specific organization's internal components or review history.

## Touch points

| File | Change |
|---|---|
| [src/sbom_tool/domain/license.clj](../src/sbom_tool/domain/license.clj) | `::component-matcher`/`::component-matchers`, `::proprietary`, `::reviewed` specs; redefine `::policies`; add shared `matches-any?`, `proprietary?`, `reviewed?`; `component-report` synthesizes a `:proprietary`/`:no-license` entry instead of an empty `:licenses` vector, then downgrades `:grey`/`:no-license` to `:reviewed` when applicable |
| [src/sbom_tool/application/report.clj](../src/sbom_tool/application/report.clj) | `unidentified-licenses`: check `proprietary?` then `reviewed?` first, new `:reason :proprietary`/`:reason :reviewed`; `license-summary`: `map` -> `keep` on `:license-id` |
| [src/sbom_tool/adapter/report/markdown.clj](../src/sbom_tool/adapter/report/markdown.clj) | `render-unidentified-licenses`: label `:proprietary`/`:reviewed`; `license-status-label`: add `:proprietary`/`:no-license`/`:reviewed`; `render-license-status-summary`: extend the status column order |
| [example-license-policy.edn](../example-license-policy.edn) | Document the `:proprietary` and `:reviewed` keys with example matchers |
| test/sbom_tool/domain/license_test.clj | `proprietary?`/`reviewed?`: name-only, name+version, purl, and non-matching cases; spec acceptance of a policy with `:proprietary`/`:reviewed`; `component-report` on a zero-license component yields `:proprietary`/`:no-license`; a grey-licensed reviewed component yields `:reviewed`; a component matching both `:proprietary` and `:reviewed` still yields `:proprietary` |
| test/sbom_tool/application/report_test.clj | `unidentified-licenses`: a proprietary component (no licenses) reports `:reason :proprietary`; a reviewed component reports `:reason :reviewed` (with and without license detail); proprietary/reviewed take precedence over an unresolved license id; `license-status-summary`/`license-summary` reflect zero-license, proprietary and reviewed components correctly (including that `license-summary` doesn't count a `nil` license id) |
| test/sbom_tool/adapter/report/markdown_test.clj | `render-unidentified-licenses`: `:proprietary`/`:reviewed` render with their labels; `render-licenses`/`render-license-status-summary`: `:proprietary`/`:no-license`/`:reviewed` render with their labels and counts |
| test/sbom_tool/adapter/policies_test.clj | Policy file with `:proprietary`/`:reviewed` sets still round-trips through `read-license-policy-file` |

## Decisions

- **Visibility gap in `licenses`/`license-status-summary`/`license-summary`:
  close it.** Proprietary, reviewed and plain no-license components must
  show up in these reports with an explicit status, not just in
  `unidentified-licenses`. See "Closing the visibility gap in
  `licenses`/summary reports" above for the `component-report` change that
  implements this (introduces the `:no-license` and `:reviewed` statuses
  alongside the new `:proprietary` one).
- **`--fail-on-violations`: no change.** A proprietary, reviewed or plain
  no-license component is not a policy violation -- each is a known,
  accepted, or at worst informational fact -- so none of them must affect
  exit status. `cli.clj`'s violation check stays scoped to
  `blacklisted-licenses` and blocked vulnerabilities exactly as today (see
  [cli.clj:152](../src/sbom_tool/adapter/ui/cli.clj#L152)); no touch point
  needed there. This is precisely why `:reviewed` is designed to never
  override `:black` (see the scope decision under "Policy shape" above):
  keeping the blacklist immune to this mechanism keeps that decision
  consistent going forward, rather than opening a silent way to defeat it.
- **`:reviewed` scope: overrides `:grey`/`:unidentified-license`/
  `:no-license`, never `:white`/`:black`.** Reviewing a component resolves
  the "needs manual attention" cases; it deliberately never reclassifies an
  already-blacklisted license. If a future need arises to record an
  explicit, reasoned exception to the blacklist itself, that should be its
  own mechanism (e.g. an `:accepted-exceptions` policy key carrying a
  reason/approver), not an extension of `:reviewed`, so the two stay
  distinguishable in an audit: "already fine, just needed a human to
  confirm it" vs. "actually against policy, but explicitly excepted."
