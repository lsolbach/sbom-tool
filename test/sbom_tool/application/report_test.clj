(ns sbom-tool.application.report-test
  (:require [clojure.test :refer [deftest is testing use-fixtures]]
            [sbom-tool.application.repository :as repo]
            [sbom-tool.application.report :as report]
            [sbom-tool.domain.sbom :as sbom]
            ; initialize adapters (registers the :cdx/:spdx read-sboms methods)
            [sbom-tool.adapter.sbom.cdx]
            [sbom-tool.adapter.sbom.spdx]))

(def mit-component
  #::sbom{:id "pkg:mit@1" :name "mit-lib" :version "1"
          :licenses #::sbom{:declared [#::sbom{:license-id "MIT"}]}})

(def gpl-component
  #::sbom{:id "pkg:gpl@1" :name "gpl-lib" :version "1"
          :licenses #::sbom{:declared [#::sbom{:license-id "GPL-3.0-only"}]}})

(def cve-1
  #::sbom{:id "CVE-2024-0001" :severity :high :affected ["pkg:mit@1"]})

(def cve-2
  #::sbom{:id "CVE-2024-0002" :severity :critical :affected ["pkg:gpl@1"]})

(def test-sbom
  #::sbom{:components [mit-component gpl-component]
          :vulnerabilities [cve-1 cve-2]})

(def license-policy
  {:default {:whitelist #{"MIT"} :blacklist #{"GPL-3.0-only"}}})

(def vulnerability-policy
  {:max-severity :high :ignored #{}})

(use-fixtures :each
  (fn [test-fn]
    (reset! repo/state {:sboms [test-sbom]
                         :policies license-policy
                         :vulnerability-policies vulnerability-policy})
    (test-fn)
    (reset! repo/state {})))

(deftest license-status-summary-test
  (testing "counts licenses per policy status"
    (is (= {:white 1 :black 1} (report/license-status-summary)))))

(deftest licenses-spdx-name-enrichment-test
  (testing "a license entry's :license-name and :license-url are nil when no license list is loaded"
    (is (every? (comp nil? :license-name) (mapcat :licenses (report/licenses))))
    (is (every? (comp nil? :license-url) (mapcat :licenses (report/licenses)))))
  (testing "loading a license list enriches resolvable entries with their canonical :license-name and :license-url"
    (swap! repo/state assoc :spdx-licenses
           {"MIT" {:name "MIT License" :license-url "https://spdx.org/licenses/MIT.html"}})
    (let [by-id (into {} (map (juxt :license-id identity)) (mapcat :licenses (report/licenses)))]
      (is (= "MIT License" (:license-name (get by-id "MIT"))))
      (is (= "https://spdx.org/licenses/MIT.html" (:license-url (get by-id "MIT"))))
      (is (nil? (:license-name (get by-id "GPL-3.0-only"))))
      (is (nil? (:license-url (get by-id "GPL-3.0-only")))))))

(deftest license-summary-test
  (testing "counts components per license id"
    (is (= {"MIT" 1 "GPL-3.0-only" 1} (report/license-summary)))))

(deftest blacklisted-licenses-test
  (testing "returns only components with at least one blacklisted license"
    (let [result (report/blacklisted-licenses)]
      (is (= 1 (count result)))
      (is (= "pkg:gpl@1" (:id (first result)))))))

(def mit-or-apache-component
  #::sbom{:id "pkg:expr@1" :name "expr-lib" :version "1"
          :licenses #::sbom{:declared [#::sbom{:license-id "MIT OR Apache-2.0"}]}})

(def mit-or-licenseref-component
  #::sbom{:id "pkg:mixed-expr@1" :name "mixed-expr-lib" :version "1"
          :licenses #::sbom{:declared [#::sbom{:license-id "MIT OR LicenseRef-custom"}]}})

(def no-license-component
  #::sbom{:id "pkg:none@1" :name "none-lib" :version "1"})

(deftest unidentified-licenses-test
  (testing "a license expression is not reported when every referenced id resolves"
    (reset! repo/state {:sboms [#::sbom{:components [mit-or-apache-component]}]})
    (is (empty? (report/unidentified-licenses))))
  (testing "a license expression is reported when at least one referenced id does not resolve"
    (reset! repo/state {:policies license-policy
                         :sboms [#::sbom{:components [mit-or-licenseref-component]}]})
    (let [result (report/unidentified-licenses)]
      (is (= #{"pkg:mixed-expr@1"} (into #{} (map :id) result)))
      (testing "each license is a license/license-entry, same shape as the `licenses` report"
        (let [entry (first (:licenses (first result)))]
          (is (= #{:license-id :license-name :license-url :status :url} (set (keys entry))))
          (is (= "MIT OR LicenseRef-custom" (:license-id entry)))
          (is (nil? (:license-name entry)))
          (is (nil? (:license-url entry)))
          (is (= :grey (:status entry))))))))

(deftest unidentified-licenses-proprietary-and-reviewed-test
  (testing "a proprietary component (no licenses) is reported with :reason :proprietary"
    (reset! repo/state {:policies (assoc license-policy :proprietary #{"none-lib"})
                         :sboms [#::sbom{:components [no-license-component]}]})
    (let [result (report/unidentified-licenses)]
      (is (= 1 (count result)))
      (is (= :proprietary (:reason (first result))))
      (is (not (contains? (first result) :licenses)))))
  (testing "proprietary takes precedence over an unresolved license id"
    (reset! repo/state {:policies (assoc license-policy :proprietary #{"mixed-expr-lib"})
                         :sboms [#::sbom{:components [mit-or-licenseref-component]}]})
    (let [result (report/unidentified-licenses)]
      (is (= :proprietary (:reason (first result))))
      (is (not (contains? (first result) :licenses)))))
  (testing "a reviewed component with no licenses is reported with :reason :reviewed and no :licenses"
    (reset! repo/state {:policies (assoc license-policy :reviewed #{"none-lib"})
                         :sboms [#::sbom{:components [no-license-component]}]})
    (let [result (report/unidentified-licenses)]
      (is (= :reviewed (:reason (first result))))
      (is (not (contains? (first result) :licenses)))))
  (testing "a reviewed component with unresolved license text is reported with :reason :reviewed and its :licenses"
    (reset! repo/state {:policies (assoc license-policy :reviewed #{"mixed-expr-lib"})
                         :sboms [#::sbom{:components [mit-or-licenseref-component]}]})
    (let [result (report/unidentified-licenses)]
      (is (= :reviewed (:reason (first result))))
      (is (= "MIT OR LicenseRef-custom" (:license-id (first (:licenses (first result))))))))
  (testing "proprietary and reviewed are resolved independently per component"
    (reset! repo/state {:policies (assoc license-policy
                                          :proprietary #{"none-lib"}
                                          :reviewed #{"mixed-expr-lib"})
                         :sboms [#::sbom{:components [no-license-component mit-or-licenseref-component]}]})
    (let [result (report/unidentified-licenses)
          by-name (into {} (map (juxt :name identity)) result)]
      (is (= :proprietary (:reason (get by-name "none-lib"))))
      (is (= :reviewed (:reason (get by-name "mixed-expr-lib")))))))

(deftest license-status-summary-gap-test
  (testing "a zero-license component counts as :no-license"
    (reset! repo/state {:policies license-policy
                         :sboms [#::sbom{:components [mit-component no-license-component]}]})
    (is (= {:white 1 :no-license 1} (report/license-status-summary))))
  (testing "a proprietary zero-license component counts as :proprietary instead"
    (reset! repo/state {:policies (assoc license-policy :proprietary #{"none-lib"})
                         :sboms [#::sbom{:components [no-license-component]}]})
    (is (= {:proprietary 1} (report/license-status-summary))))
  (testing "a reviewed component's grey status counts as :reviewed"
    (reset! repo/state {:policies (assoc license-policy :reviewed #{"mixed-expr-lib"})
                         :sboms [#::sbom{:components [mit-or-licenseref-component]}]})
    (is (= {:reviewed 1} (report/license-status-summary)))))

(deftest license-summary-gap-test
  (testing "a zero-license component's synthetic nil license id is not counted"
    (reset! repo/state {:policies license-policy
                         :sboms [#::sbom{:components [mit-component no-license-component]}]})
    (is (= {"MIT" 1} (report/license-summary)))))

(def dual-licensed-component
  #::sbom{:id "pkg:dual@1" :name "dual-lib" :version "1"
          :licenses #::sbom{:declared [#::sbom{:license-id "MIT OR GPL-3.0-only"}]}})

(deftest multi-licensed-test
  (testing "a component with more than one license choice is reported"
    (reset! repo/state {:policies license-policy
                         :spdx-licenses {"MIT" {:name "MIT License" :license-url "https://spdx.org/licenses/MIT.html"}}
                         :sboms [#::sbom{:components [dual-licensed-component]}]})
    (let [result (report/multi-licensed)]
      (is (= 1 (count result)))
      (testing "each choice is a set of license/license-entry-shaped maps, same as the `licenses` report"
        (let [entries (into #{} cat (:licenses (first result)))
              by-id (into {} (map (juxt :license-id identity)) entries)]
          (is (= #{:license-id :license-name :license-url :status} (set (keys (get by-id "MIT")))))
          (is (= "MIT License" (:license-name (get by-id "MIT"))))
          (is (= "https://spdx.org/licenses/MIT.html" (:license-url (get by-id "MIT"))))
          (is (= :white (:status (get by-id "MIT"))))
          (is (= :black (:status (get by-id "GPL-3.0-only")))))))))

(deftest vulnerabilities-by-component-test
  (testing "returns every component that has at least one vulnerability"
    (let [result (report/vulnerabilities-by-component)]
      (is (= 2 (count result)))
      (is (= #{"pkg:mit@1" "pkg:gpl@1"} (into #{} (map :id) result))))))

(deftest vulnerability-summary-test
  (testing "counts distinct vulnerabilities per severity and affected components"
    (is (= {:by-severity {:high 1 :critical 1} :affected-components 2}
           (report/vulnerability-summary)))))

(deftest blocked-vulnerabilities-test
  (testing "both high and critical are blocked at :max-severity :high"
    (is (= #{"CVE-2024-0001" "CVE-2024-0002"}
           (into #{} (map :id) (report/blocked-vulnerabilities)))))
  (testing "an ignored vulnerability id is excluded from the blocked list"
    (swap! repo/state assoc :vulnerability-policies
           {:max-severity :high :ignored #{"CVE-2024-0002"}})
    (is (= #{"CVE-2024-0001"}
           (into #{} (map :id) (report/blocked-vulnerabilities))))))

(def external-only-component
  #::sbom{:id "pkg:npm/external@1" :name "external-lib" :version "1"
          :identifiers #::sbom{:purl "pkg:npm/external@1"}})

(def external-cve
  #::sbom{:id "CVE-2024-9998" :severity :critical :source #::sbom{:name "deps.dev"}})

(deftest external-vulnerabilities-report-test
  (testing "an external-vulnerabilities entry is picked up with no SBOM-embedded vulnerabilities at all"
    (reset! repo/state {:vulnerability-policies vulnerability-policy
                         :sboms [#::sbom{:components [external-only-component]}]
                         :external-vulnerabilities {"pkg:npm/external@1" [external-cve]}})
    (let [result (report/vulnerabilities-by-component)]
      (is (= 1 (count result)))
      (is (= #{"CVE-2024-9998"} (into #{} (map :id) (:vulnerabilities (first result))))))
    (is (= {:by-severity {:critical 1} :affected-components 1}
           (report/vulnerability-summary)))
    (is (= #{"CVE-2024-9998"} (into #{} (map :id) (report/blocked-vulnerabilities))))))

(deftest consolidated-reports-e2e-test
  (testing "a package described by both a CycloneDX and an SPDX file is reported once, with both sources"
    (reset! repo/state {:policies license-policy :vulnerability-policies vulnerability-policy})
    (repo/read-sboms {:sbom-format :auto} "test/resources/sboms")
    (let [by-name (into {} (map (fn [e] [(:name e) e])) (report/licenses))
          shared (get by-name "shared-lib")]
      (is (= #{"foo" "bar" "shared-lib"} (set (keys by-name))))
      (is (= #{:cyclonedx :spdx} (set (:sources shared))))
      (is (some #(= "MIT" (:license-id %)) (:licenses shared))))
    (let [by-name (into {} (map (fn [e] [(:name e) e])) (report/vulnerabilities-by-component))
          shared (get by-name "shared-lib")]
      (is (= #{"CVE-2024-9999"} (into #{} (map :id) (:vulnerabilities shared))))
      (is (= #{:cyclonedx :spdx} (set (:sources shared)))))))
