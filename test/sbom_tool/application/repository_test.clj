(ns sbom-tool.application.repository-test
  (:require [clojure.test :refer [deftest is testing use-fixtures]]
            [sbom-tool.application.repository :as repo]
            [sbom-tool.domain.sbom :as sbom]
            [sbom-tool.domain.vulnerability :as vulnerability]
            ; initialize adapters (registers the :cdx/:spdx read-sboms methods)
            [sbom-tool.adapter.cdx.file-repository]
            [sbom-tool.adapter.spdx.file-repository]))

(def fixtures-path "test/resources/sboms")

(use-fixtures :each
  (fn [test-fn]
    (reset! repo/state {})
    (test-fn)
    (reset! repo/state {})))

(deftest read-sboms-accumulates-test
  (testing "reading a second format appends to :sboms instead of replacing it"
    (repo/read-sboms {:sbom-format :cdx} fixtures-path)
    (is (= 1 (count (repo/sboms))))
    (repo/read-sboms {:sbom-format :spdx} fixtures-path)
    (is (= 2 (count (repo/sboms))))))

(deftest read-sboms-auto-test
  (testing ":auto reads both the CycloneDX and the SPDX file in one call"
    (repo/read-sboms {:sbom-format :auto} fixtures-path)
    (is (= 2 (count (repo/sboms))))
    (is (= #{:cyclonedx :spdx}
           (into #{} (keep (comp ::sbom/format ::sbom/bom-metadata)) (repo/sboms)))))
  (testing "the components of both formats are present"
    (is (= #{"foo" "bar" "shared-lib"}
           (into #{} (map ::sbom/name) (repo/components))))))

(deftest consolidated-components-test
  (repo/read-sboms {:sbom-format :auto} fixtures-path)
  (let [by-name (into {} (map (fn [c] [(::sbom/name c) c])) (repo/consolidated-components))]
    (testing "one consolidated component per real-world package, not per document"
      (is (= #{"foo" "bar" "shared-lib"} (set (keys by-name)))))
    (testing "a package present in only one document keeps a single origin"
      (is (= 1 (count (:origins (get by-name "foo")))))
      (is (= 1 (count (:origins (get by-name "bar"))))))
    (testing "a package described by both documents merges their data and keeps both origins"
      (let [shared-lib (get by-name "shared-lib")]
        (is (= 2 (count (:origins shared-lib))))
        (is (= #::sbom{:declared [#::sbom{:license-id "MIT"}]
                       :concluded [#::sbom{:license-id "MIT"}]
                       :from-files [#::sbom{:license-id "Apache-2.0"}]}
               (::sbom/licenses shared-lib)))))
    (testing "a CVE reported only by the CycloneDX-side origin still resolves on the merged component"
      (is (= #{"CVE-2024-9999"}
             (into #{} (map ::sbom/id)
                   (vulnerability/consolidated-component-vulnerabilities
                    (get by-name "shared-lib"))))))))

(def unidentified-x
  #::sbom{:id "local-x" :name "unidentified" :version "3.0"})

(def unidentified-y
  #::sbom{:id "local-y" :name "unidentified" :version "3.0" :description "from document Y"})

(deftest merge-unidentified-flag-test
  (reset! repo/state {:sboms [#::sbom{:components [unidentified-x]}
                              #::sbom{:components [unidentified-y]}]})
  (testing "components without a purl/cpe stay unmerged by default"
    (is (= 2 (count (repo/consolidated-components)))))
  (testing "opting in via :merge-unidentified? merges them by name/version"
    (swap! repo/state assoc :merge-unidentified? true)
    (is (= 1 (count (repo/consolidated-components))))
    (is (= 2 (count (:origins (first (repo/consolidated-components))))))))
