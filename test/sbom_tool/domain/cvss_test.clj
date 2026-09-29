(ns sbom-tool.domain.cvss-test
  (:require [clojure.string :as string]
            [clojure.test :refer [deftest is testing]]
            [sbom-tool.domain.cvss :as cvss]))

(def lodash-vector
  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H")

(def scope-changed-vector
  "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H")

(def no-impact-vector
  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")

(deftest parse-vector-test
  (testing "parses a well-formed v3.1 vector"
    (is (= {:version "3.1" :av "N" :ac "L" :pr "N" :ui "N" :s "U" :c "N" :i "N" :a "H"}
           (cvss/parse-vector lodash-vector))))
  (testing "parses a well-formed v3.0 vector the same way, modulo :version"
    (is (= {:version "3.0" :av "N" :ac "L" :pr "N" :ui "N" :s "U" :c "N" :i "N" :a "H"}
           (cvss/parse-vector (string/replace lodash-vector "3.1" "3.0")))))
  (testing "rejects an unsupported CVSS version"
    (is (nil? (cvss/parse-vector "CVSS:2.0/AV:N/AC:L/Au:N/C:N/I:N/A:C")))
    (is (nil? (cvss/parse-vector "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/S:U/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N"))))
  (testing "rejects garbage and nil"
    (is (nil? (cvss/parse-vector "not-a-vector")))
    (is (nil? (cvss/parse-vector nil))))
  (testing "rejects a vector missing a required Base metric"
    (is (nil? (cvss/parse-vector "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N")))))

(deftest base-score-test
  (testing "a known-answer vector matching NVD's own published score for CVE-2020-8203"
    (is (= 7.5 (cvss/base-score (cvss/parse-vector lodash-vector)))))
  (testing "the commonly-cited Scope Changed, all-High reference vector"
    (is (= 9.6 (cvss/base-score (cvss/parse-vector scope-changed-vector)))))
  (testing "an Impact <= 0 vector scores 0.0"
    (is (= 0.0 (cvss/base-score (cvss/parse-vector no-impact-vector))))))

(deftest severity-of-score-test
  (testing "nil score is :unknown"
    (is (= :unknown (cvss/severity-of-score nil))))
  (testing "the four scored buckets"
    (is (= :low (cvss/severity-of-score 2.0)))
    (is (= :medium (cvss/severity-of-score 5.0)))
    (is (= :high (cvss/severity-of-score 7.5)))
    (is (= :critical (cvss/severity-of-score 9.6))))
  (testing "below the :low threshold is :unknown"
    (is (= :unknown (cvss/severity-of-score 0.0)))))

(deftest vector->severity-test
  (testing "nil for a garbage/nil vector string"
    (is (nil? (cvss/vector->severity "not-a-vector")))
    (is (nil? (cvss/vector->severity nil))))
  (testing "the correct severity for a valid vector"
    (is (= :high (cvss/vector->severity lodash-vector)))
    (is (= :critical (cvss/vector->severity scope-changed-vector)))))

(def max-v2-vector
  "AV:N/AC:L/Au:N/C:C/I:C/A:C")

(def apache-chunked-v2-vector
  "AV:N/AC:L/Au:N/C:N/I:N/A:C")

(def medium-v2-vector
  "AV:N/AC:L/Au:N/C:P/I:N/A:N")

(deftest parse-vector-v2-test
  (testing "parses a well-formed v2 vector (no version prefix)"
    (is (= {:av "N" :ac "L" :au "N" :c "C" :i "C" :a "C"}
           (cvss/parse-vector-v2 max-v2-vector))))
  (testing "rejects garbage and nil"
    (is (nil? (cvss/parse-vector-v2 "not-a-vector")))
    (is (nil? (cvss/parse-vector-v2 nil))))
  (testing "rejects a vector missing a required Base metric"
    (is (nil? (cvss/parse-vector-v2 "AV:N/AC:L/Au:N/C:N/I:N"))))
  (testing "rejects a v3-shaped vector (Scope isn't a v2 metric, and a v2 vector has no version prefix)"
    (is (nil? (cvss/parse-vector-v2 lodash-vector)))))

(deftest base-score-v2-test
  (testing "the maximal network/low-complexity/no-auth/complete-impact vector scores 10.0"
    (is (= 10.0 (cvss/base-score-v2 (cvss/parse-vector-v2 max-v2-vector)))))
  (testing "a known-answer vector matching NVD's own published score for CVE-2002-0392"
    (is (= 7.8 (cvss/base-score-v2 (cvss/parse-vector-v2 apache-chunked-v2-vector)))))
  (testing "a mid-range vector lands in the medium range"
    (is (= 5.0 (cvss/base-score-v2 (cvss/parse-vector-v2 medium-v2-vector))))))

(deftest severity-of-score-v2-test
  (testing "nil score is :unknown"
    (is (= :unknown (cvss/severity-of-score-v2 nil))))
  (testing "the three scored buckets"
    (is (= :low (cvss/severity-of-score-v2 2.0)))
    (is (= :medium (cvss/severity-of-score-v2 5.0)))
    (is (= :high (cvss/severity-of-score-v2 7.8))))
  (testing "below the :low threshold is :unknown"
    (is (= :unknown (cvss/severity-of-score-v2 0.0))))
  (testing "never returns :critical, even for the maximum possible score"
    (is (= :high (cvss/severity-of-score-v2 10.0)))))

(deftest vector->severity-v2-test
  (testing "nil for a garbage/nil vector string"
    (is (nil? (cvss/vector->severity-v2 "not-a-vector")))
    (is (nil? (cvss/vector->severity-v2 nil))))
  (testing "the correct severity for a valid vector"
    (is (= :high (cvss/vector->severity-v2 max-v2-vector)))
    (is (= :medium (cvss/vector->severity-v2 medium-v2-vector)))))
