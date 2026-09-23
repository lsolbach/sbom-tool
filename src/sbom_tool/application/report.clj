(ns sbom-tool.application.report
  (:require [sbom-tool.application.repository :as repo]
            [sbom-tool.domain.component :as component]
            [sbom-tool.domain.license :as license]
            [sbom-tool.domain.sbom :as sbom]
            [sbom-tool.domain.vulnerability :as vulnerability]))

(defn- with-provenance
  "Adds provenance to a component-based report `entry`: `:sources`, the
   source document formats `component` was consolidated from, and, when
   present, `:conflicts` -- the scalar fields its source documents
   disagreed on (see `sbom-tool.domain.component/merge-components`)."
  [component entry]
  (cond-> (assoc entry :sources (component/origin-sources component))
    (:conflicts component) (assoc :conflicts (:conflicts component))))

(defn licenses
  "Returns the license report for all consolidated components (one per
   real-world package, merging every source document's contribution --
   see `sbom-tool.application.repository/consolidated-components`): each
   entry's id, name, version, type and its licenses with their
   whitelist/blacklist status (:white, :black or :grey) and, when
   resolvable, their SPDX-canonical `:name`, plus `:sources` and, when the
   source documents disagreed, `:conflicts`."
  []
  (let [policies (repo/policies)
        spdx-licenses (repo/spdx-licenses)]
    (mapv (fn [component]
            (with-provenance component (license/component-report policies spdx-licenses component)))
          (repo/consolidated-components))))

(defn multi-licensed
  "Returns the consolidated components that are multi-licensed, i.e. that
   have more than one license choice -- either because their declared/
   concluded/from-files licenses disagree, or because a license
   expression offers multiple alternatives via the disjunctive OR
   operator -- together with the distinct choices. Each choice is the set
   of `license/license-entry`s (same shape as `licenses`' per-license
   entries) that must be satisfied together, which is more than one entry
   when licenses are combined via the conjunctive AND operator."
  []
  (let [policies (repo/policies)
        spdx-licenses (repo/spdx-licenses)]
    (->> (repo/consolidated-components)
         (keep (fn [component]
                 (let [choices (license/component-license-choices component)]
                   (when (> (count choices) 1)
                     (let [policy (license/policy-for policies (::sbom/component-type component))]
                       (with-provenance component
                         {:id (::sbom/id component)
                          :name (::sbom/name component)
                          :version (::sbom/version component)
                          :licenses (into #{}
                                          (map (fn [choice]
                                                 (into #{}
                                                       (map (partial license/license-entry policy spdx-licenses))
                                                       choice)))
                                          choices)}))))))
         vec)))

(defn license-status-summary
  "Returns the count of licenses per policy status (:white, :black, :grey)
   across all components."
  []
  (->> (licenses)
       (mapcat :licenses)
       (map :status)
       frequencies))

(defn license-summary
  "Returns the count of components using each license (by license id)
   across all components."
  []
  (->> (licenses)
       (mapcat :licenses)
       (map :license-id)
       frequencies))

(defn blacklisted-licenses
  "Returns the license report entries (see `licenses`) for components that
   have at least one blacklisted (`:black`) license."
  []
  (->> (licenses)
       (filterv (fn [component]
                  (some #(= :black (:status %)) (:licenses component))))))

(defn unidentified-licenses
  "Returns the components that either have no license information at all,
   or whose licenses could not be resolved to a standard SPDX license
   identifier (free-text license names, or custom LicenseRef- ids). For
   the latter, each license is a `license/license-entry` (same shape as
   `licenses`' per-license entries) plus its `:url`, if any, so free-text
   names like \"Unknown - See URL\" remain traceable to the license terms
   they refer to."
  []
  (let [policies (repo/policies)
        spdx-licenses (repo/spdx-licenses)]
    (->> (repo/consolidated-components)
         (keep (fn [component]
                 (let [licenses (license/component-licenses component)
                       policy (license/policy-for policies (::sbom/component-type component))
                       base {:id (::sbom/id component)
                             :name (::sbom/name component)
                             :version (::sbom/version component)}]
                   (cond
                     (empty? licenses)
                     (with-provenance component (assoc base :reason :no-license))

                     (not-any? license/spdx-identifiable? licenses)
                     (with-provenance component
                       (assoc base
                              :reason :unidentified-license
                              :licenses (into #{}
                                              (map (fn [lic]
                                                     (assoc (license/license-entry
                                                             policy spdx-licenses (license/license-identifier lic))
                                                            :url (license/license-url lic))))
                                              licenses)))))))
         vec)))

(defn vulnerabilities-by-component
  "Returns the vulnerability report for every consolidated component that
   has at least one vulnerability (resolved against every source document
   it was assembled from, plus any loaded `repo/external-vulnerabilities`,
   see `sbom-tool.domain.vulnerability/consolidated-component-
   vulnerabilities`): its id, name, version, type, `:sources`, and its
   vulnerabilities with their policy status (:ok, :blocked or :accepted),
   sorted by severity, most severe first."
  []
  (let [policy (repo/vulnerability-policies)
        external-vulnerabilities (repo/external-vulnerabilities)]
    (->> (repo/consolidated-components)
         (keep (fn [component]
                 (let [report (vulnerability/consolidated-component-report
                               policy component external-vulnerabilities)]
                   (when (seq (:vulnerabilities report))
                     (with-provenance component
                       (update report :vulnerabilities
                               (partial sort-by
                                        (comp #(get vulnerability/severity-rank % -1) :severity)
                                        >)))))))
         vec)))

(defn vulnerability-summary
  "Returns the count of distinct vulnerabilities per severity across all
   SBOMs, plus the count of distinct components affected by at least one
   vulnerability."
  []
  {:by-severity (->> (repo/vulnerabilities)
                     (map ::sbom/severity)
                     frequencies)
   :affected-components (count (vulnerabilities-by-component))})

(defn blocked-vulnerabilities
  "Returns the vulnerabilities across all SBOMs whose status is `:blocked`
   under the configured vulnerability policy, i.e. at or above the policy's
   `:max-severity` and not in its `:ignored` accepted-risk set."
  []
  (let [policy (repo/vulnerability-policies)]
    (->> (repo/vulnerabilities)
         (filter #(= :blocked (vulnerability/vulnerability-status policy %)))
         (mapv (fn [v] {:id (::sbom/id v)
                        :severity (::sbom/severity v)
                        :description (::sbom/description v)
                        :source (::sbom/source v)
                        :affected (::sbom/affected v)})))))
