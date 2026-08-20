(ns sbom-tool.adapter.markdown.report-test
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [sbom-tool.adapter.markdown.report :as markdown]
            [sbom-tool.application.template :as template]))

(deftest render-licenses-test
  (testing "renders one table row per component, with license/status pairs joined inline"
    (let [markdown (markdown/render-report
                    :licenses
                    [{:id "pkg:mit@1" :name "mit-lib" :version "1" :component-type :library
                      :licenses [{:license "MIT" :status :white}] :sources [:cyclonedx]}
                     {:id "pkg:gpl@1" :name "gpl-lib" :version "1" :component-type :library
                      :licenses [{:license "GPL-3.0-only" :status :black}] :sources [:spdx]}])]
      (is (str/includes? markdown "## Licenses"))
      (is (str/includes? markdown "| Component | Version | Type | Licenses | Sources |"))
      (is (str/includes? markdown "| mit-lib | 1 | library | MIT (ok) | cyclonedx |"))
      (is (str/includes? markdown "| gpl-lib | 1 | library | GPL-3.0-only (blacklisted) | spdx |")))))

(deftest render-license-summary-test
  (testing "renders a fixed-order status/count table, defaulting missing statuses to 0"
    (let [markdown (markdown/render-report :license-summary {:white 2 :black 1})]
      (is (str/includes? markdown "## License Summary"))
      (is (str/includes? markdown "| white | 2 |"))
      (is (str/includes? markdown "| grey | 0 |"))
      (is (str/includes? markdown "| black | 1 |")))))

(deftest render-multi-licensed-test
  (testing "joins choices with OR and conjunctive choices with AND"
    (let [markdown (markdown/render-report
                    :multi-licensed
                    [{:id "pkg:dual@1" :name "dual-lib" :version "1"
                      :licenses #{#{"MIT"} #{"Apache-2.0" "CC0-1.0"}}
                      :sources [:cyclonedx :spdx]}])]
      (is (or (str/includes? markdown "MIT OR (Apache-2.0 AND CC0-1.0)")
              (str/includes? markdown "(Apache-2.0 AND CC0-1.0) OR MIT")))
      (is (str/includes? markdown "cyclonedx, spdx")))))

(deftest render-unidentified-licenses-test
  (testing "renders the no-license and unidentified-license reasons as readable text"
    (let [markdown (markdown/render-report
                    :unidentified-licenses
                    [{:id "pkg:a@1" :name "a" :version "1" :reason :no-license :sources [:cyclonedx]}
                     {:id "pkg:b@1" :name "b" :version "1" :reason :unidentified-license
                      :licenses #{{:license "LicenseRef-custom"}} :sources [:spdx]}])]
      (is (str/includes? markdown "| a | 1 | no license |  | cyclonedx |"))
      (is (str/includes? markdown "| b | 1 | unidentified license | LicenseRef-custom | spdx |"))))
  (testing "appends the license URL, if any, for context"
    (let [markdown (markdown/render-report
                    :unidentified-licenses
                    [{:id "pkg:c@1" :name "c" :version "1" :reason :unidentified-license
                      :licenses #{{:license "Unknown - See URL"
                                   :url "https://example.com/license"}}
                      :sources [:spdx]}])]
      (is (str/includes? markdown
                          "| c | 1 | unidentified license | Unknown - See URL (see: https://example.com/license) | spdx |")))))

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
                    {:license-summary {:white 1}
                     :vulnerability-summary {:by-severity {} :affected-components 0}})]
      (is (not (str/includes? markdown "## All")))
      (is (str/includes? markdown "## License Summary"))
      (is (str/includes? markdown "## Vulnerability Summary")))))

(deftest render-all-license-test
  (testing "renders one heading and body per report in the :all-license bundle, without a wrapping heading"
    (let [markdown (markdown/render-report
                    :all-license
                    {:license-summary {:white 1}})]
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
    (is (str/includes? (template/render :markdown :license-summary {:white 1}) "## License Summary"))))
