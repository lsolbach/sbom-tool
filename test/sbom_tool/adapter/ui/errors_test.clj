(ns sbom-tool.adapter.ui.errors-test
  (:require [clojure.string :as string]
            [clojure.test :refer [deftest is testing]]
            [sbom-tool.adapter.ui.errors :as errors]))

(defn- ex
  ([error-type] (ex error-type {}))
  ([error-type data] (ex-info "boom" (assoc data :sbom-tool/error-type error-type)))
  ([error-type data cause] (ex-info "boom" (assoc data :sbom-tool/error-type error-type) cause)))

(deftest friendly-message-test
  (testing ":policy-file-not-found names the path"
    (is (= "Could not read the policy file some/path.edn: boom"
           (errors/friendly-message (ex :policy-file-not-found {:path "some/path.edn"})))))
  (testing ":malformed-policy-edn names the path"
    (is (= "The policy file some/path.edn is not valid EDN: boom"
           (errors/friendly-message (ex :malformed-policy-edn {:path "some/path.edn"})))))
  (testing ":invalid-policy passes the ex-message through unchanged"
    (is (= "boom" (errors/friendly-message (ex :invalid-policy)))))
  (testing ":sbom-file-not-found names the path"
    (is (= "Could not read the SBOM file some.cdx.json: boom"
           (errors/friendly-message (ex :sbom-file-not-found {:path "some.cdx.json"})))))
  (testing ":malformed-sbom-json names the path"
    (is (= "The SBOM file some.cdx.json is not valid JSON: boom"
           (errors/friendly-message (ex :malformed-sbom-json {:path "some.cdx.json"})))))
  (testing ":report-rendering-failed has no path"
    (is (= "Could not render the report: boom"
           (errors/friendly-message (ex :report-rendering-failed)))))
  (testing ":spdx-license-list-not-found names the path"
    (is (= "Could not read the SPDX license list file some/licenses.json: boom"
           (errors/friendly-message (ex :spdx-license-list-not-found {:path "some/licenses.json"})))))
  (testing ":malformed-spdx-license-list names the path"
    (is (= "The SPDX license list file some/licenses.json is not valid JSON: boom"
           (errors/friendly-message (ex :malformed-spdx-license-list {:path "some/licenses.json"})))))
  (testing "an untagged exception falls back to a generic message"
    (is (= "An unexpected error occurred: boom"
           (errors/friendly-message (ex-info "boom" {}))))))

(deftest debug-details-test
  (testing "includes every exception in the cause chain"
    (let [root (ex-info "root cause" {})
          wrapped (ex-info "wrapper" {} root)
          details (errors/debug-details wrapped)]
      (is (string/includes? details "wrapper"))
      (is (string/includes? details "root cause"))
      (is (string/includes? details "Caused by"))))
  (testing "a single exception with no cause has no \"Caused by\" section"
    (is (not (string/includes? (errors/debug-details (ex-info "solo" {})) "Caused by")))))

(deftest runtime-error-exit-code-test
  (testing "is distinct from the CLI usage/violation exit code 1"
    (is (= 2 errors/runtime-error-exit-code))))
