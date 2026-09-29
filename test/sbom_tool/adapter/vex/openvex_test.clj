(ns sbom-tool.adapter.vex.openvex-test
  (:require [clojure.test :refer [deftest is testing]]
            [sbom-tool.adapter.vex.openvex :as openvex]))

(def ^:private at-id-key
  "See `sbom-tool.adapter.vex.openvex/at-id-key` -- built via `keyword`
   rather than the `:@id` literal, which babashka's SCI reader can't parse."
  (keyword "@id"))

(def lodash-statements
  (:statements (openvex/read-vex-document "test/resources/openvex/documents/lodash.vex.json")))

(defn- statement-for
  [id]
  (first (filter #(= id (get-in % [:vulnerability :name])) lodash-statements)))

(deftest read-vex-document-test
  (testing "a missing file raises an ex-info tagged :vex-file-not-found"
    (is (= :vex-file-not-found
           (:sbom-tool/error-type
            (ex-data (try (openvex/read-vex-document "test/resources/openvex/no-such-file.vex.json")
                          (catch clojure.lang.ExceptionInfo e e)))))))
  (testing "malformed JSON raises an ex-info tagged :malformed-vex-json"
    (is (= :malformed-vex-json
           (:sbom-tool/error-type
            (ex-data (try (openvex/read-vex-document "test/resources/openvex/malformed/bad.vex.json")
                          (catch clojure.lang.ExceptionInfo e e))))))))

(deftest product-identifiers-test
  (testing "a bare @id purl string"
    (is (= {:purl "pkg:npm/lodash@4.17.15"}
           (openvex/product-identifiers {at-id-key "pkg:npm/lodash@4.17.15"}))))
  (testing "an identifiers.purl entry"
    (is (= {:purl "pkg:npm/lodash@4.17.20"}
           (openvex/product-identifiers {:identifiers {:purl "pkg:npm/lodash@4.17.20"}}))))
  (testing "an identifiers.cpe23 entry"
    (is (= {:cpe "cpe:2.3:a:lodash:lodash:4.17.20:*:*:*:*:*:*:*"}
           (openvex/product-identifiers {:identifiers {:cpe23 "cpe:2.3:a:lodash:lodash:4.17.20:*:*:*:*:*:*:*"}}))))
  (testing "a bare string product"
    (is (= {:purl "pkg:npm/chalk@4.1.0"} (openvex/product-identifiers "pkg:npm/chalk@4.1.0"))))
  (testing "an unrecognized @id scheme contributes neither"
    (is (= {} (openvex/product-identifiers {at-id-key "swid:some-tag"})))))

(deftest map-statement-test
  (testing "a not_affected statement with a justification, status-notes and an alias"
    (is (= {:vulnerability-id "CVE-2020-8203"
            :aliases ["GHSA-p6mc-m468-83gw"]
            :status :not-affected
            :justification :vulnerable-code-not-present
            :status-notes "The vulnerable merge function is never called."
            :purls #{"pkg:npm/lodash@4.17.15"}}
           (openvex/map-statement (statement-for "CVE-2020-8203")))))
  (testing "a fixed statement via identifiers.purl"
    (is (= {:vulnerability-id "CVE-2021-0001" :status :fixed :purls #{"pkg:npm/lodash@4.17.20"}}
           (openvex/map-statement (statement-for "CVE-2021-0001")))))
  (testing "an affected statement via identifiers.cpe23"
    (is (= {:vulnerability-id "CVE-2021-0002" :status :affected
            :cpes #{"cpe:2.3:a:lodash:lodash:4.17.20:*:*:*:*:*:*:*"}}
           (openvex/map-statement (statement-for "CVE-2021-0002")))))
  (testing "an unrecognized status is dropped"
    (is (nil? (openvex/map-statement (statement-for "CVE-2021-0003")))))
  (testing "a statement with no vulnerability name is dropped"
    (is (nil? (openvex/map-statement {:vulnerability {} :products [] :status "affected"})))))

(deftest read-vex-statements-test
  (testing "nil path (no VEX configured) returns nil without touching the filesystem"
    (is (nil? (openvex/read-vex-statements nil))))
  (testing "merges statements across every *.vex.json file under the path, dropping unusable ones"
    (is (= #{"CVE-2020-8203" "CVE-2021-0001" "CVE-2021-0002" "CVE-2022-0001"}
           (into #{} (map :vulnerability-id) (openvex/read-vex-statements "test/resources/openvex/documents")))))
  (testing "a directory with no *.vex.json files returns [] (with a warning, not an error)"
    (is (= [] (openvex/read-vex-statements "test/resources/policies")))))
