(ns sbom-tool.domain.component-test
  (:require [clojure.test :refer [deftest is testing]]
            [sbom-tool.domain.component :as component]
            [sbom-tool.domain.sbom :as sbom]))

(deftest component-identity-test
  (testing "prefers purl over cpe and name/version"
    (is (= "pkg:generic/foo@1.0"
           (component/component-identity
            #::sbom{:name "foo" :version "1.0"
                    :identifiers #::sbom{:purl "pkg:generic/foo@1.0"
                                          :cpe "cpe:2.3:a:foo:foo:1.0"}}))))
  (testing "falls back to cpe when there is no purl"
    (is (= "cpe:2.3:a:foo:foo:1.0"
           (component/component-identity
            #::sbom{:name "foo" :version "1.0"
                    :identifiers #::sbom{:cpe "cpe:2.3:a:foo:foo:1.0"}}))))
  (testing "without a purl/cpe, defaults to the component itself -- never merging with another"
    (let [a #::sbom{:name "foo" :version "1.0"}
          b #::sbom{:name "foo" :version "1.0" :description "from a different document"}]
      (is (= a (component/component-identity a)))
      (testing "so two distinct components sharing only a name/version do not match"
        (is (not= (component/component-identity a) (component/component-identity b))))))
  (testing "falls back to [name version] only when merge-unidentified? opts in"
    (is (= ["foo" "1.0"]
           (component/component-identity #::sbom{:name "foo" :version "1.0"} true)))
    (let [a #::sbom{:name "foo" :version "1.0"}
          b #::sbom{:name "foo" :version "1.0" :description "a different document's data"}]
      (is (= (component/component-identity a true) (component/component-identity b true))
          "opting in merges distinct components sharing a name/version")))
  (testing "two components with the same identity match"
    (let [cdx #::sbom{:name "foo" :version "1.0"
                       :identifiers #::sbom{:purl "pkg:generic/foo@1.0"}}
          spdx #::sbom{:name "foo" :version "1.0"
                       :identifiers #::sbom{:purl "pkg:generic/foo@1.0"}}]
      (is (= (component/component-identity cdx) (component/component-identity spdx))))))

(def cdx-component
  #::sbom{:id "pkg:generic/foo@1.0"
          :name "foo"
          :version "1.0"
          :component-type :other
          :identifiers #::sbom{:purl "pkg:generic/foo@1.0"}
          :hashes [#::sbom{:algorithm :sha256 :value "aaa"}]
          :licenses #::sbom{:declared [#::sbom{:license-id "MIT"}]}
          :properties {"cdx:seen" "true"}})

(def spdx-component
  #::sbom{:id "SPDXRef-Package-foo"
          :name "foo"
          :version "1.0"
          :component-type :library
          :description "The foo library"
          :identifiers #::sbom{:spdx-id "SPDXRef-Package-foo"}
          :hashes [#::sbom{:algorithm :sha256 :value "aaa"}
                   #::sbom{:algorithm :sha1 :value "bbb"}]
          :licenses #::sbom{:concluded [#::sbom{:license-id "MIT"}]
                             :from-files [#::sbom{:license-id "Apache-2.0"}]}
          :properties {"cdx:seen" "false" "spdx:extra" "1"}})

(deftest merge-components-test
  (testing "scalar fields take the first non-nil value, in the given order"
    (let [merged (component/merge-components [cdx-component spdx-component])]
      (is (= "pkg:generic/foo@1.0" (::sbom/id merged)))
      (is (= "foo" (::sbom/name merged)))
      (is (= "1.0" (::sbom/version merged)))
      (is (= "The foo library" (::sbom/description merged)))))
  (testing "component-type prefers a specific type over :other"
    (is (= :library (::sbom/component-type (component/merge-components [cdx-component spdx-component])))
        "cdx-component is :other, spdx-component is :library")
    (is (= :library (::sbom/component-type (component/merge-components [spdx-component cdx-component])))
        "order should not matter for this preference"))
  (testing "hashes are concatenated and deduplicated"
    (is (= [#::sbom{:algorithm :sha256 :value "aaa"}
            #::sbom{:algorithm :sha1 :value "bbb"}]
           (::sbom/hashes (component/merge-components [cdx-component spdx-component])))))
  (testing "identifiers are merged across components"
    (is (= #::sbom{:purl "pkg:generic/foo@1.0" :spdx-id "SPDXRef-Package-foo"}
           (::sbom/identifiers (component/merge-components [cdx-component spdx-component])))))
  (testing "licenses are merged per key across components"
    (is (= #::sbom{:declared [#::sbom{:license-id "MIT"}]
                   :concluded [#::sbom{:license-id "MIT"}]
                   :from-files [#::sbom{:license-id "Apache-2.0"}]}
           (::sbom/licenses (component/merge-components [cdx-component spdx-component])))))
  (testing "properties are merged, later components winning on key collision"
    (is (= {"cdx:seen" "false" "spdx:extra" "1"}
           (::sbom/properties (component/merge-components [cdx-component spdx-component])))))
  (testing "a single component merges into itself unchanged"
    (is (= cdx-component (component/merge-components [cdx-component]))))
  (testing "an empty string or NOASSERTION never overrides a real value, regardless of order"
    (let [real #::sbom{:id "x" :name "x" :version "1.0" :supplier "Acme"}
          blank #::sbom{:id "x" :name "x" :version "NOASSERTION" :supplier ""}]
      (is (= "1.0" (::sbom/version (component/merge-components [blank real]))))
      (is (= "Acme" (::sbom/supplier (component/merge-components [blank real]))))
      (is (= "1.0" (::sbom/version (component/merge-components [real blank]))))))
  (testing "no :conflicts when the source documents agree, or only one asserts a value"
    (is (nil? (:conflicts (component/merge-components [cdx-component spdx-component])))))
  (testing "a genuine disagreement on a scalar field is listed under :conflicts"
    (let [a #::sbom{:id "x" :name "x" :description "document A's description"}
          b #::sbom{:id "x" :name "x" :description "document B's description"}]
      (is (= {::sbom/description ["document A's description" "document B's description"]}
             (:conflicts (component/merge-components [a b]))))
      (is (= "document A's description" (::sbom/description (component/merge-components [a b])))
          "the conflict is still recorded, not lost, even though the first value wins"))))

(deftest origin-sources-test
  (testing "returns the distinct source document formats across :origins"
    (is (= [:cyclonedx :spdx]
           (component/origin-sources
            {:origins [{:sbom #::sbom{:bom-metadata #::sbom{:format :cyclonedx}}}
                       {:sbom #::sbom{:bom-metadata #::sbom{:format :spdx}}}
                       {:sbom #::sbom{:bom-metadata #::sbom{:format :cyclonedx}}}]}))))
  (testing "returns an empty vector for a component with no origins or no bom-metadata"
    (is (= [] (component/origin-sources {:origins []})))
    (is (= [] (component/origin-sources {:origins [{:sbom #::sbom{}}]})))))
