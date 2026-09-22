(ns sbom-tool.adapter.license.spdx-test
  (:require [clojure.test :refer [deftest is testing]]
            [sbom-tool.adapter.license.spdx :as spdx]))

(deftest read-license-list-test
  (testing "reads the bundled default license list, including a well-known id"
    (let [licenses (spdx/read-license-list nil)]
      (is (= "MIT License" (:name (get licenses "MIT"))))
      (is (= "https://spdx.org/licenses/MIT.html" (:license-url (get licenses "MIT"))))
      (is (false? (:deprecated? (get licenses "MIT"))))
      (is (true? (:osi-approved? (get licenses "MIT"))))))
  (testing "reads a given license list file"
    (let [licenses (spdx/read-license-list "test/resources/spdx/sample-license-list.json")]
      (is (= #{"MIT" "AGPL-1.0"} (set (keys licenses))))
      (is (= "MIT License" (:name (get licenses "MIT"))))
      (is (= "https://spdx.org/licenses/MIT.html" (:license-url (get licenses "MIT"))))
      (is (true? (:deprecated? (get licenses "AGPL-1.0"))))))
  (testing "a missing file raises an ex-info tagged :spdx-license-list-not-found"
    (is (= :spdx-license-list-not-found
           (:sbom-tool/error-type
            (ex-data (try (spdx/read-license-list "test/resources/spdx/no-such-file.json")
                          (catch clojure.lang.ExceptionInfo e e)))))))
  (testing "malformed JSON raises an ex-info tagged :malformed-spdx-license-list"
    (is (= :malformed-spdx-license-list
           (:sbom-tool/error-type
            (ex-data (try (spdx/read-license-list "test/resources/spdx/broken.json")
                          (catch clojure.lang.ExceptionInfo e e))))))))
