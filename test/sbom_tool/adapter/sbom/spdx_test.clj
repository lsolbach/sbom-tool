(ns sbom-tool.adapter.sbom.spdx-test
  (:require [clojure.test :refer [deftest is testing]]
            [sbom-tool.adapter.sbom.spdx :as spdx]))

(deftest read-json-test
  (testing "reads a valid SPDX file"
    (is (some? (spdx/read-json "test/resources/sboms/sample.spdx.json"))))
  (testing "a missing file raises an ex-info tagged :sbom-file-not-found"
    (is (= :sbom-file-not-found
           (:sbom-tool/error-type
            (ex-data (try (spdx/read-json "test/resources/sboms/no-such-file.spdx.json")
                          (catch clojure.lang.ExceptionInfo e e))))))))
