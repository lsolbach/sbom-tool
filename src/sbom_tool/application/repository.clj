(ns sbom-tool.application.repository
  (:require [sbom-tool.domain.sbom :as sbom]))

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
  "Return the SBOM format from options."
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
