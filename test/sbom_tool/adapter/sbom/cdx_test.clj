(ns sbom-tool.adapter.sbom.cdx-test
  (:require [clojure.test :refer [deftest is testing]]
            [sbom-tool.adapter.sbom.cdx :as cdx]))

(deftest read-json-test
  (testing "reads a valid CycloneDX file"
    (is (some? (cdx/read-json "test/resources/sboms/sample.cdx.json"))))
  (testing "a missing file raises an ex-info tagged :sbom-file-not-found"
    (is (= :sbom-file-not-found
           (:sbom-tool/error-type
            (ex-data (try (cdx/read-json "test/resources/sboms/no-such-file.cdx.json")
                          (catch clojure.lang.ExceptionInfo e e)))))))
  (testing "malformed JSON raises an ex-info tagged :malformed-sbom-json"
    (is (= :malformed-sbom-json
           (:sbom-tool/error-type
            (ex-data (try (cdx/read-json "test/resources/sboms/malformed.json")
                          (catch clojure.lang.ExceptionInfo e e))))))))
