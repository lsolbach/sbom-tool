(ns sbom-tool.util.functions-test
  (:require [clojure.string :as string]
            [clojure.test :refer [deftest is testing]]
            [sbom-tool.util.functions :as fns])
  (:import [java.io File StringWriter]))

(deftest bounded-pmap-test
  (testing "returns the results in input order"
    (is (= [0 2 4 6 8 10]
           (fns/bounded-pmap 3 (fn [x] (Thread/sleep (long (- 50 (* 10 x)))) (* 2 x)) (range 6)))))
  (testing "never runs more than n tasks at once"
    (let [running (atom 0)
          peak (atom 0)]
      (fns/bounded-pmap 2
                        (fn [_]
                          (swap! peak max (swap! running inc))
                          (Thread/sleep 30)
                          (swap! running dec))
                        (range 8))
      (is (<= @peak 2))))
  (testing "an exception in a task surfaces to the caller"
    (is (thrown? Exception
                 (fns/bounded-pmap 2 (fn [x] (if (= x 1) (throw (ex-info "boom" {})) x)) (range 3))))))

(deftest warn-test
  (testing "writes to stderr and leaves stdout alone"
    (let [err (StringWriter.)
          out (with-out-str (binding [*err* err] (fns/warn "something failed")))]
      (is (= "" out))
      (is (= "Warning: something failed" (string/trim (str err)))))))

(deftest url-encode-test
  (testing "encodes reserved characters and spaces"
    (is (= "a%2Fb%40c+d" (fns/url-encode "a/b@c d"))))
  (testing "leaves unreserved characters alone"
    (is (= "lodash-4.17_1" (fns/url-encode "lodash-4.17_1")))))

(defn- temp-file
  [content]
  (let [file (File/createTempFile "api-key" ".edn")]
    (.deleteOnExit file)
    (spit file content)
    (str file)))

(def ^:private error-types
  {:not-found-error-type :test-key-file-not-found
   :malformed-error-type :test-malformed-key-edn})

(deftest read-api-key-file-test
  (testing "returns the :api-key of the file"
    (is (= "secret" (fns/read-api-key-file (temp-file "{:api-key \"secret\"}") error-types))))
  (testing "a file without :api-key yields nil"
    (is (nil? (fns/read-api-key-file (temp-file "{}") error-types))))
  (testing "a missing file throws the caller's not-found error type, with the path"
    (let [ex (try (fns/read-api-key-file "/nonexistent/key.edn" error-types)
                  (catch clojure.lang.ExceptionInfo e e))]
      (is (= :test-key-file-not-found (:sbom-tool/error-type (ex-data ex))))
      (is (= "/nonexistent/key.edn" (:path (ex-data ex))))
      (is (= "file not found: /nonexistent/key.edn" (ex-message ex)))))
  (testing "malformed EDN throws the caller's malformed error type, with the path"
    (let [path (temp-file "{:api-key")
          ex (try (fns/read-api-key-file path error-types)
                  (catch clojure.lang.ExceptionInfo e e))]
      (is (= :test-malformed-key-edn (:sbom-tool/error-type (ex-data ex))))
      (is (= path (:path (ex-data ex))))
      (is (string/starts-with? (ex-message ex) "malformed EDN: ")))))
