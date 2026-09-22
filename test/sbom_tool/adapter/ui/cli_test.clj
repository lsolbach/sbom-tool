(ns sbom-tool.adapter.ui.cli-test
  (:require [clojure.string :as string]
            [clojure.test :refer [deftest is testing use-fixtures]]
            [sbom-tool.adapter.ui.cli :as cli]
            [sbom-tool.application.repository :as repo]))

(use-fixtures :each
  (fn [test-fn]
    (reset! repo/state {})
    (test-fn)
    (reset! repo/state {})))

(def ^:private base-options
  "A full options map as `validate-args` would produce it, pointed at the
   shared SBOM fixtures and the bundled default policies."
  {:input-path "test/resources/sboms"
   :sbom-format :auto
   :license-policy nil
   :vulnerability-policy nil
   :merge-unidentified false
   :report :all-license
   :output-format :edn
   :fail-on-violations false
   :debug false})

(deftest run-happy-path-test
  (testing "a successful run prints the report and returns nil"
    (is (nil? (cli/run base-options)))))

(deftest run-missing-policy-file-test
  (testing "a missing --license-policy file is reported at exit code 2, not thrown"
    (let [{:keys [exit-code message]} (cli/run (assoc base-options
                                                       :license-policy "test/resources/policies/no-such-file.edn"))]
      (is (= 2 exit-code))
      (is (string/includes? message "no-such-file.edn")))))

(deftest run-malformed-policy-file-test
  (testing "a syntactically broken --license-policy file is reported at exit code 2"
    (let [{:keys [exit-code message]} (cli/run (assoc base-options
                                                       :license-policy "test/resources/policies/broken.edn"))]
      (is (= 2 exit-code))
      (is (string/includes? message "not valid EDN")))))

(deftest run-debug-appends-cause-chain-test
  (testing "--debug appends the exception's cause chain on top of the friendly message"
    (let [{:keys [message]} (cli/run (assoc base-options
                                             :license-policy "test/resources/policies/no-such-file.edn"
                                             :debug true))]
      (is (string/includes? message "Caused by")))))

(deftest run-spdx-license-list-test
  (testing "an overriding --spdx-license-list is loaded and used to enrich license entries"
    (is (nil? (cli/run (assoc base-options
                               :spdx-license-list "test/resources/spdx/sample-license-list.json")))))
  (testing "a missing --spdx-license-list file is reported at exit code 2, not thrown"
    (let [{:keys [exit-code message]} (cli/run (assoc base-options
                                                       :spdx-license-list "test/resources/spdx/no-such-file.json"))]
      (is (= 2 exit-code))
      (is (string/includes? message "no-such-file.json")))))

(deftest run-fail-on-violations-test
  (testing "--fail-on-violations exits 1 when a blocked vulnerability is found"
    (let [{:keys [exit-code]} (cli/run (assoc base-options
                                               :vulnerability-policy "example-vulnerability-policy.edn"
                                               :fail-on-violations true))]
      (is (= 1 exit-code)))))
