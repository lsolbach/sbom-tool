(ns sbom-tool.adapter.ui.cli
  "Commandline interface"
  (:require [clojure.string :as str]
            [clojure.tools.cli :as cli]
            [sbom-tool.application.report :as report]
            [sbom-tool.application.template :as template]
            ; initialize adapter
            [sbom-tool.adapter.sbom.cdx :as cdx-repo]
            [sbom-tool.adapter.sbom.spdx :as spdx-repo]
            [sbom-tool.adapter.policy.file-repository :as policy-repo]
            [sbom-tool.adapter.report.markdown :as markdown-report]
            [sbom-tool.adapter.report.json :as json-report]
            [sbom-tool.application.repository :as repo])
  (:gen-class))

(def appname "sbom-tool.jar")

(def description
  "Reads SBOMs and reports e.g. licenses.")

(def ^:private all-license-reports
  "The license reports bundled by `:all-license`."
  (fn []
    {:licenses (report/licenses)
     :license-status-summary (report/license-status-summary)
     :license-summary (report/license-summary)
     :multi-licensed (report/multi-licensed)
     :unidentified-licenses (report/unidentified-licenses)
     :blacklisted-licenses (report/blacklisted-licenses)}))

(def ^:private all-vulnerability-reports
  "The vulnerability reports bundled by `:all-vulnerabilities`. Kept out of
   the `:all-license` default because most SBOMs carry no vulnerability
   data at all, and reporting zero vulnerabilities in that case reads as
   \"scanned, none found\" rather than \"nothing to say\" -- so callers
   must opt into vulnerability reporting explicitly."
  (fn []
    {:vulnerabilities (report/vulnerabilities-by-component)
     :vulnerability-summary (report/vulnerability-summary)
     :blocked-vulnerabilities (report/blocked-vulnerabilities)}))

(def reports
  "Map of `--report` keyword to the no-arg report function it invokes.
   `:all-license` bundles every license report, `:all-vulnerabilities`
   bundles every vulnerability report, and `:all` bundles both, each keyed
   the same way as this map."
  {:licenses report/licenses
   :license-status-summary report/license-status-summary
   :license-summary report/license-summary
   :multi-licensed report/multi-licensed
   :unidentified-licenses report/unidentified-licenses
   :blacklisted-licenses report/blacklisted-licenses
   :vulnerabilities report/vulnerabilities-by-component
   :vulnerability-summary report/vulnerability-summary
   :blocked-vulnerabilities report/blocked-vulnerabilities
   :all-license all-license-reports
   :all-vulnerabilities all-vulnerability-reports
   :all (fn []
          (merge (all-license-reports) (all-vulnerability-reports)))})

(def cli-opts
  "Commandline options specification."
  [["-I" "--input-path PATH" "Path of the SBOM folder" :default "sboms"]
   ["-l" "--license-policy PATH" "Path of the license policy file"]
   ["-V" "--vulnerability-policy PATH" "Path of the vulnerability policy file"]
   ["-s" "--sbom-format FORMAT" "Format of the SBOMs: auto (both), cdx or spdx" :default :auto :parse-fn keyword]
   ["-m" "--merge-unidentified" "Also merge components across documents that carry neither a purl nor a cpe, by name/version alone -- riskier, since unrelated packages can coincidentally share both across ecosystems"]
   ["-r" "--report REPORT" (str "Report to generate, one of: " (str/join ", " (map name (keys reports))))
    :default :all-license
    :parse-fn keyword
    :validate [(set (keys reports))
               (str "Must be one of: " (str/join ", " (map name (keys reports))))]]
   ["-o" "--output-format FORMAT" "Output format: edn, json or markdown"
    :default :edn
    :parse-fn keyword
    :validate [#{:edn :json :markdown} "Must be one of: edn, json, markdown"]]
   ["-f" "--fail-on-violations" "Exit with status 1 if there are blacklisted licenses or policy-blocked vulnerabilities"]
   ["-h" "--help" "Print help"]])

(defn usage-msg
  "Returns a message containing the program usage."
  ([summary]
   (usage-msg (str "java --jar " appname ".jar [options]") "" summary))
  ([name summary]
   (usage-msg name "" summary))
  ([name description summary]
   (str/join "\n\n"
             [description
              (str "Usage: java -jar " name ".jar [options].")
              "Options:"
              summary])))

(defn error-msg
  "Returns a message containing the parsing errors."
  [errors]
  (str "The following errors occurred while parsing your command:\n\n"
       (str/join \newline errors)))

(defn exit
  "Exits the process."
  [status msg]
  (println msg)
  (System/exit status))

(defn validate-args
  "Validate command line arguments `args` according to the given `cli-opts`.
   Either returns a map indicating the program should exit
   (with an error message and optional success status), or a map
   indicating the options provided."
  [args cli-opts]
  (try
    (let [{:keys [options arguments errors summary]} (cli/parse-opts args cli-opts)]
      (cond
        errors ; errors => exit with description of errors
        {:exit-message (error-msg errors)}
        (:help options) ; help => exit OK with usage summary
        {:exit-message (usage-msg appname description summary) :success true}
        (= 0 (count arguments)) ; no args
        {:options options}
        (seq options)
        {:options options}
        :else ; failed custom validation => exit with usage summary
        {:exit-message (usage-msg appname description summary)}))
    (catch Exception e
      (println "Error validating the CLI arguments" args ".")
      (println (ex-message e))
      (.printStacktrace e))))

(defn initialize-state
  "Initialize the program state."
  [options]
  ; TODO use destructuring
  (swap! repo/state assoc :merge-unidentified? (:merge-unidentified options))
  (repo/read-sboms options (:input-path options))
  (repo/read-policies options (:license-policy options))
  (repo/read-vulnerability-policies options (:vulnerability-policy options)))

(defn violations?
  "Returns true if there are any blacklisted licenses or policy-blocked
   vulnerabilities across the SBOMs, given the currently loaded policies."
  []
  (or (seq (report/blacklisted-licenses))
      (seq (report/blocked-vulnerabilities))))

(defn dispatch
  "Dispatch on options: prints the requested `--report`, defaulting to
   `all-license`, rendered in the requested `--output-format` (`:edn`,
   printed as-is, or `:json`/`:markdown`, rendered via `template/render`),
   and, when `--fail-on-violations` is set, exits with status 1 if
   `violations?` is true."
  [options]
  (let [report-key (:report options)
        report-fn (get reports report-key all-license-reports)
        data (report-fn)
        output-format (:output-format options)]
    (if (= :edn output-format)
      (println data)
      (println (template/render output-format report-key data))))
  (when (and (:fail-on-violations options) (violations?))
    (System/exit 1)))

(defn handle
  "Initialize the state and handle the options."
  [options]
  (initialize-state options)
  (dispatch options)
  )

(defn -main
  "Main function as CLI entry point."
  [& args]
  (let [{:keys [options exit-message success]} (validate-args args cli-opts)
        ; options (merge default-options options)
        exit-message (or exit-message
                         (when (:help options)
                           (usage-msg appname description (:summary options))))]
    (when (:debug options)
      (println options))
    (if exit-message
      ; exit with message
      (exit (if success 0 1) exit-message)
      ; handle options and generate the requested outputs
      (handle options))))

(comment
  (-main "--help")
  ;
  )
