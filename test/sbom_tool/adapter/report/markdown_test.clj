(ns sbom-tool.adapter.report.markdown-test
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [sbom-tool.adapter.report.markdown :as markdown]
            [sbom-tool.application.template :as template]))

(deftest render-licenses-test
  (testing "renders one table row per component, with explicit license id/name/status columns"
    (let [markdown (markdown/render-report
                    :licenses
                    [{:id "pkg:mit@1" :name "mit-lib" :version "1" :component-type :library
                      :licenses [{:license-id "MIT" :license-name "MIT License" :status :white}]
                      :sources [:cyclonedx]}
                     {:id "pkg:gpl@1" :name "gpl-lib" :version "1" :component-type :library
                      :licenses [{:license-id "GPL-3.0-only" :license-name nil :status :black}] :sources [:spdx]}])]
      (is (str/includes? markdown "## Licenses"))
      (is (str/includes? markdown "| Component | Version | Type | License ID | License Name | Status | Sources |"))
      (is (str/includes? markdown "| mit-lib | 1 | library | MIT | MIT License | ok | cyclonedx |"))
      (testing "an entry with no resolved :license-name falls back to its :license-id"
        (is (str/includes? markdown "| gpl-lib | 1 | library | GPL-3.0-only | GPL-3.0-only | blacklisted | spdx |")))))
  (testing "renders a single blank-license row for a component with no licenses at all"
    (let [markdown (markdown/render-report
                    :licenses
                    [{:id "pkg:none@1" :name "none-lib" :version "1" :component-type :library
                      :licenses [] :sources [:cyclonedx]}])]
      (is (str/includes? markdown "| none-lib | 1 | library |  |  |  | cyclonedx |"))))
  (testing "renders the :proprietary, :no-license and :reviewed statuses with their own labels"
    (let [markdown (markdown/render-report
                    :licenses
                    [{:id "pkg:prop@1" :name "prop-lib" :version "1" :component-type :library
                      :licenses [{:license-id nil :license-name nil :license-url nil :status :proprietary}]
                      :sources [:cyclonedx]}
                     {:id "pkg:none@1" :name "none-lib" :version "1" :component-type :library
                      :licenses [{:license-id nil :license-name nil :license-url nil :status :no-license}]
                      :sources [:cyclonedx]}
                     {:id "pkg:rev@1" :name "rev-lib" :version "1" :component-type :library
                      :licenses [{:license-id "Beerware" :license-name nil :status :reviewed}]
                      :sources [:cyclonedx]}])]
      (is (str/includes? markdown "| prop-lib | 1 | library |  |  | proprietary | cyclonedx |"))
      (is (str/includes? markdown "| none-lib | 1 | library |  |  | no license | cyclonedx |"))
      (is (str/includes? markdown "| rev-lib | 1 | library | Beerware | Beerware | reviewed | cyclonedx |"))))
  (testing "links the license name to its :license-url, when known"
    (let [markdown (markdown/render-report
                    :licenses
                    [{:id "pkg:mit@1" :name "mit-lib" :version "1" :component-type :library
                      :licenses [{:license-id "MIT" :license-name "MIT License"
                                  :license-url "https://spdx.org/licenses/MIT.html" :status :white}]
                      :sources [:cyclonedx]}])]
      (is (str/includes? markdown "[MIT License](https://spdx.org/licenses/MIT.html)"))))
  (testing "renders the plain name, not a broken link, when :license-url is absent"
    (let [markdown (markdown/render-report
                    :licenses
                    [{:id "pkg:mit@1" :name "mit-lib" :version "1" :component-type :library
                      :licenses [{:license-id "MIT" :license-name "MIT License" :status :white}]
                      :sources [:cyclonedx]}])]
      (is (str/includes? markdown "| mit-lib | 1 | library | MIT | MIT License | ok | cyclonedx |"))
      (is (not (str/includes? markdown "["))))))

(deftest render-license-status-summary-test
  (testing "renders a fixed-order status/count table, defaulting missing statuses to 0"
    (let [markdown (markdown/render-report :license-status-summary {:white 2 :black 1})]
      (is (str/includes? markdown "## License Status Summary"))
      (is (str/includes? markdown "| white | 2 |"))
      (is (str/includes? markdown "| grey | 0 |"))
      (is (str/includes? markdown "| black | 1 |"))
      (is (str/includes? markdown "| proprietary | 0 |"))
      (is (str/includes? markdown "| no-license | 0 |"))
      (is (str/includes? markdown "| reviewed | 0 |"))))
  (testing "renders non-zero :proprietary, :no-license and :reviewed counts"
    (let [markdown (markdown/render-report :license-status-summary
                                            {:white 1 :proprietary 2 :no-license 3 :reviewed 4})]
      (is (str/includes? markdown "| proprietary | 2 |"))
      (is (str/includes? markdown "| no-license | 3 |"))
      (is (str/includes? markdown "| reviewed | 4 |")))))

(deftest render-license-summary-test
  (testing "renders a count-per-license table, most-used license first"
    (let [markdown (markdown/render-report :license-summary {"MIT" 1 "Apache-2.0" 3})]
      (is (str/includes? markdown "## License Summary"))
      (is (str/includes? markdown "| License | Count |"))
      (is (str/includes? markdown "| Apache-2.0 | 3 |"))
      (is (str/includes? markdown "| MIT | 1 |"))
      (is (< (str/index-of markdown "Apache-2.0") (str/index-of markdown "| MIT"))))))

(deftest render-multi-licensed-test
  (testing "renders one row per choice, joining a choice's conjunctive (AND) entries within each column"
    (let [markdown (markdown/render-report
                    :multi-licensed
                    [{:id "pkg:dual@1" :name "dual-lib" :version "1"
                      :licenses #{#{{:license-id "MIT" :license-name "MIT License"
                                     :license-url "https://spdx.org/licenses/MIT.html" :status :white}}
                                  #{{:license-id "Apache-2.0" :license-name nil :status :white}
                                    {:license-id "CC0-1.0" :license-name "Creative Commons Zero v1.0 Universal" :status :white}}}
                      :sources [:cyclonedx :spdx]}])]
      (is (str/includes? markdown "## Multi-licensed Components"))
      (is (str/includes? markdown "| Component | Version | License ID | License Name | Status | Sources |"))
      (testing "a single-entry choice links its name to its URL, when known"
        (is (str/includes? markdown "| dual-lib | 1 | MIT | [MIT License](https://spdx.org/licenses/MIT.html) | ok | cyclonedx, spdx |")))
      (is (str/includes? markdown
                          "| dual-lib | 1 | Apache-2.0 AND CC0-1.0 | Apache-2.0 AND Creative Commons Zero v1.0 Universal | ok AND ok | cyclonedx, spdx |")))))

(deftest render-unidentified-licenses-test
  (testing "renders the no-license and unidentified-license reasons as readable text"
    (let [markdown (markdown/render-report
                    :unidentified-licenses
                    [{:id "pkg:a@1" :name "a" :version "1" :reason :no-license :sources [:cyclonedx]}
                     {:id "pkg:b@1" :name "b" :version "1" :reason :unidentified-license
                      :licenses #{{:license-id "LicenseRef-custom" :license-name nil :status :grey}}
                      :sources [:spdx]}])]
      (is (str/includes? markdown "## Unidentified Licenses"))
      (is (str/includes? markdown
                          "| Component | Version | Reason | License ID | License Name | Status | URL | Sources |"))
      (is (str/includes? markdown "| a | 1 | no license |  |  |  |  | cyclonedx |"))
      (testing "an entry with no resolved :license-name falls back to its :license-id"
        (is (str/includes? markdown "| b | 1 | unidentified license | LicenseRef-custom | LicenseRef-custom | review |  | spdx |")))))
  (testing "includes the license's own declared :url in its own column -- distinct from :license-url, the SPDX reference link"
    (let [markdown (markdown/render-report
                    :unidentified-licenses
                    [{:id "pkg:c@1" :name "c" :version "1" :reason :unidentified-license
                      :licenses #{{:license-id "Unknown - See URL" :license-name nil :status :grey
                                   :url "https://example.com/license"}}
                      :sources [:spdx]}])]
      (is (str/includes? markdown
                          "| c | 1 | unidentified license | Unknown - See URL | Unknown - See URL | review | https://example.com/license | spdx |")))))
  (testing "renders the proprietary and reviewed reasons as readable text"
    (let [markdown (markdown/render-report
                    :unidentified-licenses
                    [{:id "pkg:d@1" :name "d" :version "1" :reason :proprietary :sources [:cyclonedx]}
                     {:id "pkg:e@1" :name "e" :version "1" :reason :reviewed
                      :licenses #{{:license-id "LicenseRef-custom" :license-name nil :status :reviewed}}
                      :sources [:spdx]}])]
      (is (str/includes? markdown "| d | 1 | proprietary |  |  |  |  | cyclonedx |"))
      (is (str/includes? markdown "| e | 1 | reviewed | LicenseRef-custom | LicenseRef-custom | reviewed |  | spdx |"))))

(deftest render-vulnerabilities-test
  (testing "joins each component's vulnerabilities inline with severity and status"
    (let [markdown (markdown/render-report
                    :vulnerabilities
                    [{:id "pkg:a@1" :name "a" :version "1" :component-type :library
                      :vulnerabilities [{:id "CVE-1" :severity :high :status :blocked}]
                      :sources [:cyclonedx]}])]
      (is (str/includes? markdown "## Vulnerabilities"))
      (is (str/includes? markdown "| a | 1 | library | CVE-1 (high, blocked) | cyclonedx |"))))
  (testing "links well-formed CVE ids to their opencve.io record"
    (let [markdown (markdown/render-report
                    :vulnerabilities
                    [{:id "pkg:a@1" :name "a" :version "1" :component-type :library
                      :vulnerabilities [{:id "CVE-2026-71038" :severity :high :status :blocked}]
                      :sources [:cyclonedx]}])]
      (is (str/includes? markdown
                          "[CVE-2026-71038](https://app.opencve.io/cve/CVE-2026-71038) (high, blocked)")))))

(deftest render-vulnerability-summary-test
  (testing "renders severities in a fixed most-to-least-severe order plus the affected count"
    (let [markdown (markdown/render-report
                    :vulnerability-summary
                    {:by-severity {:high 2 :critical 1} :affected-components 3})]
      (is (str/includes? markdown "| critical | 1 |"))
      (is (str/includes? markdown "| high | 2 |"))
      (is (str/includes? markdown "| medium | 0 |"))
      (is (str/includes? markdown "Affected components: 3")))))

(deftest render-blocked-vulnerabilities-test
  (testing "renders one row per blocked vulnerability"
    (let [markdown (markdown/render-report
                    :blocked-vulnerabilities
                    [{:id "CVE-1" :severity :critical :affected ["pkg:a@1"] :description "bad"}])]
      (is (str/includes? markdown "| CVE-1 | critical | pkg:a@1 | bad |"))))
  (testing "links well-formed CVE ids to their opencve.io record"
    (let [markdown (markdown/render-report
                    :blocked-vulnerabilities
                    [{:id "CVE-2026-71038" :severity :critical :affected ["pkg:a@1"] :description "bad"}])]
      (is (str/includes? markdown
                          "| [CVE-2026-71038](https://app.opencve.io/cve/CVE-2026-71038) | critical | pkg:a@1 | bad |")))))

(deftest render-empty-report-test
  (testing "renders a placeholder instead of an empty table"
    (is (str/includes? (markdown/render-report :licenses []) "_none_"))))

(deftest render-all-test
  (testing "renders one heading and body per report in the :all bundle, without a wrapping heading"
    (let [markdown (markdown/render-report
                    :all
                    {:license-summary {"MIT" 1}
                     :vulnerability-summary {:by-severity {} :affected-components 0}})]
      (is (not (str/includes? markdown "## All")))
      (is (str/includes? markdown "## License Summary"))
      (is (str/includes? markdown "## Vulnerability Summary")))))

(deftest render-all-license-test
  (testing "renders one heading and body per report in the :all-license bundle, without a wrapping heading"
    (let [markdown (markdown/render-report
                    :all-license
                    {:license-summary {"MIT" 1}})]
      (is (not (str/includes? markdown "## All")))
      (is (str/includes? markdown "## License Summary")))))

(deftest render-all-vulnerabilities-test
  (testing "renders one heading and body per report in the :all-vulnerabilities bundle, without a wrapping heading"
    (let [markdown (markdown/render-report
                    :all-vulnerabilities
                    {:vulnerability-summary {:by-severity {} :affected-components 0}})]
      (is (not (str/includes? markdown "## All")))
      (is (str/includes? markdown "## Vulnerability Summary")))))

(deftest template-render-dispatch-test
  (testing "the :markdown format is registered on the application template port"
    (is (str/includes? (template/render :markdown :license-summary {"MIT" 1}) "## License Summary"))))
