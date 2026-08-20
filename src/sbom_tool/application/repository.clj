(ns sbom-tool.application.repository
  (:require [sbom-tool.domain.component :as component]
            [sbom-tool.domain.sbom :as sbom]))

(def state (atom {}))

(defn policies
  "Returns the policies."
  []
  (:policies @state))

(defn sboms
  "Returns the SBOMs."
  []
  (:sboms @state))

(defn components
  "Returns the set of components for the SBOMs"
  []
  (->> (sboms)
       (mapcat ::sbom/components)
       (into #{})))

(defn sbom-components
  "Returns [sbom component] pairs for every component across all SBOMs, one
   pair per SBOM the component appears in. Unlike `components`, this does not
   deduplicate across SBOMs, so a component stays paired with the SBOM whose
   `::sbom/vulnerabilities` it can be resolved against."
  []
  (for [sbom (sboms)
        component (::sbom/components sbom)]
    [sbom component]))

(defn merge-unidentified?
  "Returns whether `consolidated-components` is allowed to merge
   components that carry neither a `::purl` nor a `::cpe` across
   documents by their `[name version]` alone -- disabled unless the CLI's
   `--merge-unidentified` flag set it in `state`, since that fallback
   identity is a heuristic: unrelated packages coincidentally sharing a
   name and version (plausible across ecosystems) would be wrongly
   merged."
  []
  (boolean (:merge-unidentified? @state)))

(defn consolidated-components
  "Returns one consolidated `::sbom/component` per real-world package
   across all SBOMs, merging every source document's contribution to it
   (see `sbom-tool.domain.component/merge-components`) -- e.g. a library
   described by both a CycloneDX and an SPDX file becomes a single entry
   carrying both documents' data. Each merged component carries an
   `:origins` key: a vector of `{:sbom sbom :component-id id}` maps, one
   per source document it was assembled from, since `::sbom/affected`
   vulnerability ids are only meaningful within their own document (see
   `sbom-components`) and so cannot be resolved directly against the
   merged component's own id. Components without a `::purl`/`::cpe` are
   only merged across documents by name/version when `merge-unidentified?`
   allows it; otherwise each stays its own, unmerged entry."
  []
  (let [merge-unidentified (merge-unidentified?)]
    (->> (sbom-components)
         (group-by (fn [[_ component]] (component/component-identity component merge-unidentified)))
         (mapv (fn [[_ pairs]]
                 (let [origins (mapv (fn [[sbom component]]
                                        {:sbom sbom :component-id (::sbom/id component)})
                                      pairs)]
                   (assoc (component/merge-components (map second pairs))
                          :origins origins)))))))

(defn vulnerabilities
  "Returns the set of distinct vulnerabilities across all SBOMs."
  []
  (->> (sboms)
       (mapcat ::sbom/vulnerabilities)
       (into #{})))

(defn vulnerability-policies
  "Returns the vulnerability policy."
  []
  (:vulnerability-policies @state))

(defn policy-source
  "Return the SBOM format from options."
  ([options]
   ;(:license-policy-file options)
   :file
   )
  ([options & _]
   ;(:license-policy-file options)
   :file
   ))

(defn sbom-format
  "Return the SBOM format from options: `:cdx`, `:spdx`, or `:auto` to read
   every CycloneDX and SPDX file under the path in one call."
  ([options]
   (:sbom-format options))
  ([options _]
   (:sbom-format options)))

(defn vulnerability-policy-source
  "Return the vulnerability policy source from options."
  ([_options]
   :file)
  ([_options & _]
   :file))

(defmulti read-policies
  "Reads the SBOMs"
  policy-source)

(defmulti read-vulnerability-policies
  "Reads the vulnerability policy."
  vulnerability-policy-source)

(defmulti read-sboms
  "Reads the SBOMs"
  sbom-format)

;; Reads every CycloneDX and SPDX file under `path`, accumulating both into
;; `:sboms` (each format's `read-sboms` method appends rather than
;; replaces, see the `:cdx`/`:spdx` methods).
(defmethod read-sboms :auto
  [options path]
  (read-sboms (assoc options :sbom-format :cdx) path)
  (read-sboms (assoc options :sbom-format :spdx) path))
