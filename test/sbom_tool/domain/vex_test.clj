(ns sbom-tool.domain.vex-test
  (:require [clojure.test :refer [deftest is testing]]
            [sbom-tool.domain.sbom :as sbom]
            [sbom-tool.domain.vex :as vex]))

(def purl-component
  #::sbom{:id "c1" :name "shared" :identifiers #::sbom{:purl "pkg:npm/shared@1.0"}})

(def cpe-component
  #::sbom{:id "c2" :name "shared" :identifiers #::sbom{:cpe "cpe:2.3:a:vendor:shared:1.0"}})

(def unidentified-component
  #::sbom{:id "c3" :name "shared"})

(def statement-not-affected
  {:vulnerability-id "CVE-2024-0001" :status :not-affected
   :justification :vulnerable-code-not-present
   :purls #{"pkg:npm/shared@1.0"}})

(def statement-affected
  {:vulnerability-id "CVE-2024-0001" :status :affected
   :purls #{"pkg:npm/shared@1.0"}})

(def statement-cpe
  {:vulnerability-id "CVE-2024-0002" :status :fixed
   :cpes #{"cpe:2.3:a:vendor:shared:1.0"}})

(def statement-alias
  {:vulnerability-id "GHSA-xxxx-yyyy-zzzz" :aliases ["CVE-2024-0003"] :status :not-affected
   :purls #{"pkg:npm/shared@1.0"}})

(deftest matching-statements-test
  (testing "matches by purl"
    (is (= [statement-not-affected]
           (vex/matching-statements [statement-not-affected] purl-component "CVE-2024-0001"))))
  (testing "matches by cpe when there is no purl"
    (is (= [statement-cpe]
           (vex/matching-statements [statement-cpe] cpe-component "CVE-2024-0002"))))
  (testing "matches an alias, case-insensitively"
    (is (= [statement-alias]
           (vex/matching-statements [statement-alias] purl-component "cve-2024-0003"))))
  (testing "no match when the vulnerability id differs"
    (is (= [] (vex/matching-statements [statement-not-affected] purl-component "CVE-9999-9999"))))
  (testing "no match when the component has neither purl nor cpe"
    (is (= [] (vex/matching-statements [statement-not-affected] unidentified-component "CVE-2024-0001"))))
  (testing "no match when the component's purl isn't in the statement's :purls"
    (is (= [] (vex/matching-statements [statement-not-affected]
                                        #::sbom{:id "c4" :identifiers #::sbom{:purl "pkg:npm/other@2.0"}}
                                        "CVE-2024-0001")))))

(deftest vex-entry-test
  (testing "returns the status and justification of the single matching statement"
    (is (= {:status :not-affected :justification :vulnerable-code-not-present}
           (vex/vex-entry [statement-not-affected] purl-component "CVE-2024-0001"))))
  (testing "returns the status-notes when present"
    (is (= {:status :fixed :notes "patched in 1.1"}
           (vex/vex-entry [(assoc statement-cpe :status-notes "patched in 1.1")]
                           cpe-component "CVE-2024-0002"))))
  (testing "nil when nothing matches"
    (is (nil? (vex/vex-entry [statement-not-affected] purl-component "CVE-9999-9999"))))
  (testing "nil when statements is nil (no VEX configured)"
    (is (nil? (vex/vex-entry nil purl-component "CVE-2024-0001"))))
  (testing "affected beats not-affected when statements conflict"
    (is (= :affected (:status (vex/vex-entry [statement-not-affected statement-affected]
                                               purl-component "CVE-2024-0001")))))
  (testing "under-investigation beats fixed when statements conflict"
    (let [under-investigation {:vulnerability-id "CVE-2024-0002" :status :under-investigation
                                :cpes #{"cpe:2.3:a:vendor:shared:1.0"}}]
      (is (= :under-investigation
             (:status (vex/vex-entry [statement-cpe under-investigation] cpe-component "CVE-2024-0002")))))))

(deftest exempted?-test
  (testing "not-affected and fixed exempt"
    (is (true? (vex/exempted? {:status :not-affected})))
    (is (true? (vex/exempted? {:status :fixed}))))
  (testing "affected and under-investigation do not exempt"
    (is (false? (vex/exempted? {:status :affected})))
    (is (false? (vex/exempted? {:status :under-investigation}))))
  (testing "nil (no matching statement) does not exempt"
    (is (false? (vex/exempted? nil)))))
