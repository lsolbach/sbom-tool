(ns sbom-tool.adapter.json.report-test
  (:require [cheshire.core :as json]
            [clojure.test :refer [deftest is testing]]
            [sbom-tool.adapter.json.report]
            [sbom-tool.application.template :as template]))

(deftest template-render-dispatch-test
  (testing "the :json format is registered on the application template port"
    (let [rendered (template/render :json :license-summary {:white 1 :black 0})]
      (is (= {"white" 1 "black" 0} (json/parse-string rendered))))))

(deftest render-report-test
  (testing "serializes keywords (both keys and values) as plain strings"
    (let [rendered (template/render :json :licenses
                                     [{:id "pkg:mit@1" :name "mit-lib" :version "1"
                                       :component-type :library
                                       :licenses [{:license "MIT" :status :white}]}])]
      (is (= [{"id" "pkg:mit@1" "name" "mit-lib" "version" "1"
               "component-type" "library"
               "licenses" [{"license" "MIT" "status" "white"}]}]
             (json/parse-string rendered)))))
  (testing "renders an empty report as an empty JSON array"
    (is (= [] (json/parse-string (template/render :json :licenses [])))))
  (testing "renders the :all bundle as a single JSON object keyed by report name"
    (let [rendered (template/render :json :all
                                     {:license-summary {:white 1}
                                      :vulnerability-summary {:by-severity {} :affected-components 0}})]
      (is (= {"license-summary" {"white" 1}
              "vulnerability-summary" {"by-severity" {} "affected-components" 0}}
             (json/parse-string rendered))))))
