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
   whitelist/blacklist status (:white, :black or :grey), plus `:sources`
   and, when the source documents disagreed, `:conflicts`."
  []
  (let [policies (repo/policies)]
    (mapv (fn [component]
            (with-provenance component (license/component-report policies component)))
          (repo/consolidated-components))))

(defn multi-licensed
  "Returns the consolidated components that are multi-licensed, i.e. that
   have more than one license choice -- either because their declared/
   concluded/from-files licenses disagree, or because a license
   expression offers multiple alternatives via the disjunctive OR
   operator -- together with the distinct choices. Each choice is the set
   of license ids that must be satisfied together, which is more than one
   id when licenses are combined via the conjunctive AND operator."
  []
  (->> (repo/consolidated-components)
       (keep (fn [component]
               (let [choices (license/component-license-choices component)]
                 (when (> (count choices) 1)
                   (with-provenance component
                     {:id (::sbom/id component)
                      :name (::sbom/name component)
                      :version (::sbom/version component)
                      :licenses choices})))))
       vec))

(defn license-summary
  "Returns the count of licenses per policy status (:white, :black, :grey)
   across all components."
  []
  (->> (licenses)
       (mapcat :licenses)
       (map :status)
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
   the latter, each license is reported together with its URL, if any,
   so free-text names like \"Unknown - See URL\" remain traceable to the
   license terms they refer to."
  []
  (->> (repo/consolidated-components)
       (keep (fn [component]
               (let [licenses (license/component-licenses component)
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
                                            (map (fn [license]
                                                   {:license (license/license-identifier license)
                                                    :url (license/license-url license)}))
                                            licenses)))))))
       vec))

(defn vulnerabilities-by-component
  "Returns the vulnerability report for every consolidated component that
   has at least one vulnerability (resolved against every source document
   it was assembled from, see `sbom-tool.domain.vulnerability/
   consolidated-component-vulnerabilities`): its id, name, version, type,
   `:sources`, and its vulnerabilities with their policy status (:ok,
   :blocked or :accepted), sorted by severity, most severe first."
  []
  (let [policy (repo/vulnerability-policies)]
    (->> (repo/consolidated-components)
         (keep (fn [component]
                 (let [report (vulnerability/consolidated-component-report policy component)]
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
