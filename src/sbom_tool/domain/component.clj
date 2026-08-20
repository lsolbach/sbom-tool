(ns sbom-tool.domain.component
  "Pure domain logic for recognizing and merging components that describe
   the same real-world package across different SBOM documents (e.g. the
   same library reported by both a CycloneDX and an SPDX file)."
  (:require [clojure.string :as string]
            [sbom-tool.domain.sbom :as sbom]))

(defn component-identity
  "Returns an identity value for `component`, used to recognize the same
   real-world package across different SBOM documents: its `::purl` if
   present (the strongest signal -- stable and ecosystem-qualified), else
   its `::cpe`. Without either, `component` itself is returned as its own
   (necessarily unique) identity, so it never merges with anything else --
   unless `merge-unidentified?` is true, in which case its `[name version]`
   pair is used as a last-resort fallback identity shared by both
   CycloneDX and SPDX documents. That fallback is opt-in because it is a
   heuristic, not a guarantee: unrelated packages that happen to share a
   name and version (plausible across ecosystems) would be treated as the
   same."
  ([component] (component-identity component false))
  ([component merge-unidentified?]
   (or (get-in component [::sbom/identifiers ::sbom/purl])
       (get-in component [::sbom/identifiers ::sbom/cpe])
       (when merge-unidentified? [(::sbom/name component) (::sbom/version component)])
       component)))

(defn- blank-value?
  "Returns true for values that must never win a merge over a real one:
   nil, blank strings, the SPDX `NOASSERTION` placeholder (in case it
   reaches this far uncleaned), and `:other`, the catch-all component
   type meaning \"unknown\" rather than an actual, disagreeing value."
  [v]
  (or (nil? v)
      (= :other v)
      (and (string? v)
           (or (string/blank? v)
               (= "NOASSERTION" (string/upper-case v))))))

(defn- first-value
  "Returns the first value of `k` across `components`, in order, that is
   not blank (see `blank-value?`)."
  [k components]
  (some #(let [v (k %)] (when-not (blank-value? v) v)) components))

(def ^:private conflict-keys
  "Scalar `::component` fields worth flagging when source documents
   disagree on their value."
  [::sbom/name ::sbom/version ::sbom/description ::sbom/copyright
   ::sbom/supplier ::sbom/manufacturer ::sbom/component-type])

(defn- scalar-conflicts
  "Returns a map of field key to the distinct non-blank values found for
   it across `components`, for every field in `conflict-keys` where more
   than one such value exists -- i.e. the source documents genuinely
   disagree, rather than one of them simply not asserting a value."
  [components]
  (into {}
        (keep (fn [k]
                (let [values (into [] (comp (map k) (remove blank-value?) (distinct)) components)]
                  (when (> (count values) 1)
                    [k values]))))
        conflict-keys))

(defn- merge-component-type
  "Returns the first `::component-type` across `components` that is more
   specific than `:other`, falling back to the first `:other`/absent one."
  [components]
  (let [types (keep ::sbom/component-type components)]
    (or (first (remove #{:other} types))
        (first types))))

(defn- merge-collection
  "Concatenates the `k` collections across `components`, deduplicated,
   preserving first-seen order."
  [k components]
  (not-empty (into [] (distinct) (mapcat k components))))

(defn- merge-identifiers
  "Merges `::identifiers` maps across `components`; the first component to
   carry a given key wins."
  [components]
  (not-empty (apply merge (reverse (keep ::sbom/identifiers components)))))

(defn- merge-licenses
  "Merges `::licenses` maps across `components`: `::declared`, `::concluded`
   and `::from-files` are each concatenated and deduplicated across every
   component that carries them -- e.g. combining a CycloneDX document's
   `::declared` licenses with an SPDX document's `::concluded` and
   `::from-files` license analysis for the same package."
  [components]
  (let [licenses-maps (keep ::sbom/licenses components)]
    (not-empty
     (into {}
           (keep (fn [k]
                   (when-let [vs (merge-collection k licenses-maps)]
                     [k vs])))
           [::sbom/declared ::sbom/concluded ::sbom/from-files]))))

(defn- merge-properties
  "Merges `::properties` maps across `components`; later components win on
   key collision."
  [components]
  (not-empty (apply merge (keep ::sbom/properties components))))

(defn merge-components
  "Merges `components` -- `::sbom/component`s that all share the same
   `component-identity` -- into a single consolidated component, e.g.
   because one document describes a package via CycloneDX and another via
   SPDX. Scalar fields (`::id`, `::name`, `::version`, `::description`,
   `::copyright`, `::supplier`, `::manufacturer`) take the first non-blank
   value across `components`, in the given order -- neither an empty
   value nor the SPDX `NOASSERTION` placeholder overrides a real one, see
   `blank-value?`; `::component-type` additionally prefers a specific type
   over `:other`; `::hashes` and `::external-references` are concatenated
   and deduplicated; `::identifiers`, `::licenses` and `::properties` are
   merged key by key. When `components` genuinely disagree on a scalar
   field's value (more than one distinct non-blank value), the result
   also carries a `:conflicts` key (see `scalar-conflicts`), so the
   dropped alternatives are not silently lost."
  [components]
  (into {}
        (remove (comp nil? val))
        {::sbom/id (first-value ::sbom/id components)
         ::sbom/name (first-value ::sbom/name components)
         ::sbom/version (first-value ::sbom/version components)
         ::sbom/description (first-value ::sbom/description components)
         ::sbom/copyright (first-value ::sbom/copyright components)
         ::sbom/supplier (first-value ::sbom/supplier components)
         ::sbom/manufacturer (first-value ::sbom/manufacturer components)
         ::sbom/component-type (merge-component-type components)
         ::sbom/identifiers (merge-identifiers components)
         ::sbom/hashes (merge-collection ::sbom/hashes components)
         ::sbom/external-references (merge-collection ::sbom/external-references components)
         ::sbom/licenses (merge-licenses components)
         ::sbom/properties (merge-properties components)
         :conflicts (not-empty (scalar-conflicts components))}))

(defn origin-sources
  "Returns the distinct source document `::sbom/format`s (e.g.
   `:cyclonedx`, `:spdx`) that contributed to a consolidated `component`,
   one per distinct format found across its `:origins` (see
   `sbom-tool.application.repository/consolidated-components`)."
  [component]
  (into [] (distinct) (keep (comp ::sbom/format ::sbom/bom-metadata :sbom) (:origins component))))
