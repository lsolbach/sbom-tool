(ns sbom-tool.domain.license-test
  (:require [clojure.test :refer [deftest is testing]]
            [sbom-tool.domain.license :as license]
            [sbom-tool.domain.sbom :as sbom]))

(deftest spdx-identifiable-test
  (testing "a plain SPDX license id is identifiable"
    (is (true? (license/spdx-identifiable? #::sbom{:license-id "MIT"}))))
  (testing "a custom LicenseRef- id is not identifiable"
    (is (false? (license/spdx-identifiable? #::sbom{:license-id "LicenseRef-custom"}))))
  (testing "a compound expression is identifiable when every referenced id is"
    (is (true? (license/spdx-identifiable? #::sbom{:license-id "MIT OR Apache-2.0"})))
    (is (true? (license/spdx-identifiable? #::sbom{:license-id "MIT AND Apache-2.0"}))))
  (testing "a compound expression is not identifiable when any referenced id is not"
    (is (false? (license/spdx-identifiable? #::sbom{:license-id "MIT OR LicenseRef-custom"})))
    (is (false? (license/spdx-identifiable? #::sbom{:license-id "(MIT OR LicenseRef-custom) AND Apache-2.0"}))))
  (testing "a license with no id at all, only a free-text name, is never identifiable"
    (is (nil? (license/spdx-identifiable? #::sbom{:license-name "Unknown - See URL"})))))

(def sample-spdx-licenses
  {"MIT" {:name "MIT License" :license-url "https://spdx.org/licenses/MIT.html"
          :deprecated? false :osi-approved? true}})

(deftest spdx-license-name-test
  (testing "resolves the canonical name for a directly recognized id"
    (is (= "MIT License" (license/spdx-license-name sample-spdx-licenses "MIT"))))
  (testing "returns nil for an id not present in the license list"
    (is (nil? (license/spdx-license-name sample-spdx-licenses "Apache-2.0"))))
  (testing "returns nil for a compound expression, even if every id in it resolves"
    (is (nil? (license/spdx-license-name sample-spdx-licenses "MIT OR MIT"))))
  (testing "returns nil when no license list was loaded"
    (is (nil? (license/spdx-license-name nil "MIT")))))

(deftest spdx-license-url-test
  (testing "resolves the SPDX reference URL for a directly recognized id"
    (is (= "https://spdx.org/licenses/MIT.html" (license/spdx-license-url sample-spdx-licenses "MIT"))))
  (testing "returns nil for an id not present in the license list"
    (is (nil? (license/spdx-license-url sample-spdx-licenses "Apache-2.0"))))
  (testing "returns nil for a compound expression, even if every id in it resolves"
    (is (nil? (license/spdx-license-url sample-spdx-licenses "MIT OR MIT"))))
  (testing "returns nil when no license list was loaded"
    (is (nil? (license/spdx-license-url nil "MIT")))))

(deftest component-report-name-enrichment-test
  (let [component #::sbom{:id "pkg:a@1" :name "a" :version "1"
                          :licenses #::sbom{:declared [#::sbom{:license-id "MIT"}
                                                        #::sbom{:license-id "Beerware"}]}}
        report (license/component-report {} sample-spdx-licenses component)
        by-license (into {} (map (juxt :license-id identity)) (:licenses report))]
    (testing "every entry has explicit :license-id, :license-name, :license-url and :status fields"
      (is (every? #(= #{:license-id :license-name :license-url :status} (set (keys %))) (:licenses report))))
    (testing "a license resolved against the SPDX list carries its canonical name and URL"
      (is (= "MIT License" (:license-name (get by-license "MIT"))))
      (is (= "https://spdx.org/licenses/MIT.html" (:license-url (get by-license "MIT")))))
    (testing "a license not found in the SPDX list carries a nil :license-name and :license-url"
      (is (nil? (:license-name (get by-license "Beerware"))))
      (is (nil? (:license-url (get by-license "Beerware")))))
    (testing "no license list at all leaves every entry's :license-name and :license-url nil"
      (let [report (license/component-report {} nil component)]
        (is (every? (comp nil? :license-name) (:licenses report)))
        (is (every? (comp nil? :license-url) (:licenses report)))))))

(deftest proprietary?-test
  (testing "matches by bare name against any version"
    (is (true? (license/proprietary? #{"acme-lib"} #::sbom{:id "1" :name "acme-lib" :version "1.0"}))))
  (testing "does not match a different name"
    (is (false? (license/proprietary? #{"acme-lib"} #::sbom{:id "1" :name "other-lib" :version "1.0"}))))
  (testing "a {:name :version} matcher only matches that exact version"
    (is (true? (license/proprietary? #{{:name "acme-lib" :version "2.0"}}
                                      #::sbom{:id "1" :name "acme-lib" :version "2.0"})))
    (is (false? (license/proprietary? #{{:name "acme-lib" :version "2.0"}}
                                       #::sbom{:id "1" :name "acme-lib" :version "1.0"}))))
  (testing "a {:purl} matcher matches by purl regardless of name"
    (is (true? (license/proprietary? #{{:purl "pkg:generic/acme/tool"}}
                                      #::sbom{:id "1" :name "different-name"
                                              :identifiers #::sbom{:purl "pkg:generic/acme/tool"}}))))
  (testing "an empty proprietary set matches nothing"
    (is (false? (license/proprietary? #{} #::sbom{:id "1" :name "acme-lib"})))))

(deftest reviewed?-test
  (testing "matches under the same rule as proprietary?"
    (is (true? (license/reviewed? #{"vendor-sdk"} #::sbom{:id "1" :name "vendor-sdk" :version "1.0"})))
    (is (false? (license/reviewed? #{"vendor-sdk"} #::sbom{:id "1" :name "other" :version "1.0"})))))

(deftest component-report-no-license-and-proprietary-test
  (let [component #::sbom{:id "pkg:none@1" :name "none-lib" :version "1"}]
    (testing "a component with no licenses at all gets a synthetic :no-license entry"
      (let [report (license/component-report {} nil component)]
        (is (= [{:license-id nil :license-name nil :license-url nil :status :no-license}]
               (:licenses report)))))
    (testing "a component matching :proprietary gets a synthetic :proprietary entry instead"
      (let [report (license/component-report {:proprietary #{"none-lib"}} nil component)]
        (is (= :proprietary (:status (first (:licenses report)))))))))

(deftest component-report-reviewed-test
  (let [grey-component #::sbom{:id "pkg:grey@1" :name "grey-lib" :version "1"
                                :licenses #::sbom{:declared [#::sbom{:license-id "Beerware"}]}}
        no-license-component #::sbom{:id "pkg:none@1" :name "none-lib" :version "1"}
        mit-component #::sbom{:id "pkg:mit@1" :name "mit-lib" :version "1"
                               :licenses #::sbom{:declared [#::sbom{:license-id "MIT"}]}}]
    (testing "a reviewed component's grey license is downgraded to :reviewed"
      (let [report (license/component-report {:reviewed #{"grey-lib"}} nil grey-component)]
        (is (= :reviewed (:status (first (:licenses report)))))))
    (testing "a reviewed component's synthetic :no-license entry is downgraded to :reviewed"
      (let [report (license/component-report {:reviewed #{"none-lib"}} nil no-license-component)]
        (is (= :reviewed (:status (first (:licenses report)))))))
    (testing "reviewed never downgrades :white"
      (let [report (license/component-report {:default {:whitelist #{"MIT"}} :reviewed #{"mit-lib"}}
                                               nil mit-component)]
        (is (= :white (:status (first (:licenses report)))))))
    (testing "reviewed never downgrades :black"
      (let [gpl-component #::sbom{:id "pkg:gpl@1" :name "gpl-lib" :version "1"
                                   :licenses #::sbom{:declared [#::sbom{:license-id "GPL-3.0-only"}]}}
            report (license/component-report {:default {:blacklist #{"GPL-3.0-only"}} :reviewed #{"gpl-lib"}}
                                               nil gpl-component)]
        (is (= :black (:status (first (:licenses report)))))))
    (testing "a component matching both :proprietary and :reviewed stays :proprietary"
      (let [report (license/component-report {:proprietary #{"none-lib"} :reviewed #{"none-lib"}}
                                               nil no-license-component)]
        (is (= :proprietary (:status (first (:licenses report)))))))))
