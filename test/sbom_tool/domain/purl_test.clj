(ns sbom-tool.domain.purl-test
  (:require [clojure.test :refer [deftest is testing]]
            [sbom-tool.domain.purl :as purl]))

(deftest parse-purl-test
  (testing "a plain purl with no namespace"
    (is (= {:type "npm" :namespace nil :name "lodash" :version "4.17.15"}
           (purl/parse-purl "pkg:npm/lodash@4.17.15"))))
  (testing "an npm scoped package's namespace is percent-decoded"
    (is (= {:type "npm" :namespace "@colors" :name "colors" :version "1.5.0"}
           (purl/parse-purl "pkg:npm/%40colors/colors@1.5.0"))))
  (testing "a Maven purl's namespace is its group id"
    (is (= {:type "maven" :namespace "com.google.guava" :name "guava" :version "31.1-jre"}
           (purl/parse-purl "pkg:maven/com.google.guava/guava@31.1-jre"))))
  (testing "a Go purl's namespace can itself contain slashes"
    (is (= {:type "golang" :namespace "github.com/gin-gonic" :name "gin" :version "v1.9.0"}
           (purl/parse-purl "pkg:golang/github.com/gin-gonic/gin@v1.9.0"))))
  (testing "qualifiers and a subpath are discarded"
    (is (= {:type "npm" :namespace nil :name "lodash" :version "4.17.15"}
           (purl/parse-purl "pkg:npm/lodash@4.17.15?os=linux#sub/path"))))
  (testing "a purl with no version does not parse"
    (is (nil? (purl/parse-purl "pkg:npm/lodash"))))
  (testing "a non-purl string does not parse"
    (is (nil? (purl/parse-purl "cpe:2.3:a:lodash:lodash:4.17.15:*:*:*:*:*:*:*")))
    (is (nil? (purl/parse-purl nil)))))

(deftest qualified-name-test
  (testing "Maven joins namespace and name with a colon"
    (is (= "com.google.guava:guava"
           (purl/qualified-name {:type "maven" :namespace "com.google.guava" :name "guava"}))))
  (testing "a namespaced non-Maven type joins with a slash"
    (is (= "@colors/colors"
           (purl/qualified-name {:type "npm" :namespace "@colors" :name "colors"}))))
  (testing "no namespace returns the bare name"
    (is (= "lodash" (purl/qualified-name {:type "npm" :namespace nil :name "lodash"})))))
