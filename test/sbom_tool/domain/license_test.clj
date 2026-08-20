(ns sbom-tool.domain.license-test
  (:require [clojure.test :refer [deftest is testing]]
            [sbom-tool.domain.license :as license]
            [sbom-tool.domain.sbom :as sbom]))

(deftest spdx-identifiable-test
  (testing "a plain SPDX license id is identifiable"
    (is (true? (license/spdx-identifiable? #::sbom{:license-id "MIT"}))))
  (testing "a custom LicenseRef- id is not identifiable"
    (is (false? (license/spdx-identifiable? #::sbom{:license-id "LicenseRef-custom"}))))
  (testing "a compound expression is identifiable when every referenced id is"
    (is (true? (license/spdx-identifiable? #::sbom{:license-id "MIT OR Apache-2.0"})))
    (is (true? (license/spdx-identifiable? #::sbom{:license-id "MIT AND Apache-2.0"}))))
  (testing "a compound expression is not identifiable when any referenced id is not"
    (is (false? (license/spdx-identifiable? #::sbom{:license-id "MIT OR LicenseRef-custom"})))
    (is (false? (license/spdx-identifiable? #::sbom{:license-id "(MIT OR LicenseRef-custom) AND Apache-2.0"}))))
  (testing "a license with no id at all, only a free-text name, is never identifiable"
    (is (nil? (license/spdx-identifiable? #::sbom{:license-name "Unknown - See URL"})))))
