(ns sbom-tool.adapter.policies-test
  (:require [clojure.test :refer [deftest is testing]]
            [sbom-tool.adapter.policies :as policies]))

(deftest read-license-policy-file-test
  (testing "reads the bundled default policy when no path is given"
    (is (contains? (policies/read-license-policy-file nil) :default)))
  (testing "reads a given policy file"
    (is (contains? (policies/read-license-policy-file "example-license-policy.edn") :library)))
  (testing "a policy file's :proprietary and :reviewed sets round-trip through validation"
    (let [policy (policies/read-license-policy-file "example-license-policy.edn")]
      (is (contains? (:proprietary policy) "acme-internal-lib"))
      (is (contains? (:reviewed policy) "beerware-fork"))))
  (testing "a missing file raises an ex-info tagged :policy-file-not-found"
    (is (= :policy-file-not-found
           (:sbom-tool/error-type
            (ex-data (try (policies/read-license-policy-file "test/resources/policies/no-such-file.edn")
                          (catch clojure.lang.ExceptionInfo e e)))))))
  (testing "malformed EDN raises an ex-info tagged :malformed-policy-edn"
    (is (= :malformed-policy-edn
           (:sbom-tool/error-type
            (ex-data (try (policies/read-license-policy-file "test/resources/policies/broken.edn")
                          (catch clojure.lang.ExceptionInfo e e))))))))

(deftest read-vulnerability-policy-file-test
  (testing "reads the bundled default policy when no path is given"
    (is (contains? (policies/read-vulnerability-policy-file nil) :max-severity)))
  (testing "reads a given policy file"
    (is (= :high (:max-severity (policies/read-vulnerability-policy-file "example-vulnerability-policy.edn")))))
  (testing "a policy that fails its spec raises an ex-info tagged :invalid-policy"
    (is (= :invalid-policy
           (:sbom-tool/error-type
            (ex-data (try (policies/read-vulnerability-policy-file "test/resources/policies/invalid-vulnerability-policy.edn")
                          (catch clojure.lang.ExceptionInfo e e))))))))
