(ns sbom-tool.application.report-test
  (:require [clojure.test :refer [deftest is testing use-fixtures]]
            [sbom-tool.application.repository :as repo]
            [sbom-tool.application.report :as report]
            [sbom-tool.domain.sbom :as sbom]
            ; initialize adapters (registers the :cdx/:spdx read-sboms methods)
            [sbom-tool.adapter.sbom.cdx]
            [sbom-tool.adapter.spdx.spdx]))

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

(deftest unidentified-licenses-test
  (testing "a license expression is not reported when every referenced id resolves"
    (reset! repo/state {:sboms [#::sbom{:components [mit-or-apache-component]}]})
    (is (empty? (report/unidentified-licenses))))
  (testing "a license expression is reported when at least one referenced id does not resolve"
    (reset! repo/state {:sboms [#::sbom{:components [mit-or-licenseref-component]}]})
    (is (= #{"pkg:mixed-expr@1"} (into #{} (map :id) (report/unidentified-licenses))))))

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

(deftest consolidated-reports-e2e-test
  (testing "a package described by both a CycloneDX and an SPDX file is reported once, with both sources"
    (reset! repo/state {:policies license-policy :vulnerability-policies vulnerability-policy})
    (repo/read-sboms {:sbom-format :auto} "test/resources/sboms")
    (let [by-name (into {} (map (fn [e] [(:name e) e])) (report/licenses))
          shared (get by-name "shared-lib")]
      (is (= #{"foo" "bar" "shared-lib"} (set (keys by-name))))
      (is (= #{:cyclonedx :spdx} (set (:sources shared))))
      (is (some #(= "MIT" (:license %)) (:licenses shared))))
    (let [by-name (into {} (map (fn [e] [(:name e) e])) (report/vulnerabilities-by-component))
          shared (get by-name "shared-lib")]
      (is (= #{"CVE-2024-9999"} (into #{} (map :id) (:vulnerabilities shared))))
      (is (= #{:cyclonedx :spdx} (set (:sources shared)))))))
