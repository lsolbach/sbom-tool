(ns sbom-tool.adapter.markdown.report
  "Renders `sbom-tool.application.report` reports as markdown. A hand-rolled
   renderer per report shape for now; a future template-engine-based
   adapter (e.g. using comb, as in Overarch) can replace this without any
   change to the application or CLI layers, since both register under the
   same `:markdown` format via `sbom-tool.application.template/render`."
  (:require [clojure.string :as str]
            [sbom-tool.application.template :as template]))

(defn- md-escape
  "Escapes `s` for use inside a markdown table cell."
  [s]
  (-> (str s)
      (str/replace "|" "\\|")
      (str/replace "\n" " ")))

(defn- md-table-row
  [cells]
  (str "| " (str/join " | " (map md-escape cells)) " |"))

(defn- md-table
  "Renders `rows` (a seq of seqs of cell values) as a markdown table with
   `headers`, or a placeholder line if `rows` is empty."
  [headers rows]
  (if (empty? rows)
    "_none_\n"
    (str (md-table-row headers) "\n"
         (md-table-row (repeat (count headers) "---")) "\n"
         (str/join "\n" (map md-table-row rows))
         "\n")))

(def ^:private license-status-label
  {:white "ok" :black "blacklisted" :grey "review"})

(defn- format-license-entry
  [{:keys [license status]}]
  (str license " (" (get license-status-label status (name status)) ")"))

(def ^:private vulnerability-status-label
  {:ok "ok" :blocked "blocked" :accepted "accepted"})

(defn- format-vulnerability-entry
  [{:keys [id severity status]}]
  (str id " (" (name severity) ", " (get vulnerability-status-label status (name status)) ")"))

(defn- format-choice
  "Formats one license choice (a set of license ids that must be satisfied
   together) as e.g. \"MIT\" or \"(MIT AND Apache-2.0)\"."
  [choice]
  (if (> (count choice) 1)
    (str "(" (str/join " AND " (sort choice)) ")")
    (first choice)))

(defn- render-licenses
  [data]
  (md-table ["Component" "Version" "Type" "Licenses"]
            (for [entry data]
              [(:name entry) (:version entry)
               (some-> (:component-type entry) name)
               (str/join "; " (map format-license-entry (:licenses entry)))])))

(defn- render-license-summary
  [data]
  (md-table ["Status" "Count"]
            (for [status [:white :grey :black]]
              [(name status) (str (get data status 0))])))

(defn- render-multi-licensed
  [data]
  (md-table ["Component" "Version" "Choices"]
            (for [entry data]
              [(:name entry) (:version entry)
               (str/join " OR " (map format-choice (:licenses entry)))])))

(defn- format-unidentified-license
  [{:keys [license url]}]
  (if url
    (str license " (see: " url ")")
    (str license)))

(defn- render-unidentified-licenses
  [data]
  (md-table ["Component" "Version" "Reason" "Licenses"]
            (for [entry data]
              [(:name entry) (:version entry)
               (case (:reason entry)
                 :no-license "no license"
                 :unidentified-license "unidentified license"
                 (name (:reason entry)))
               (str/join "; " (map format-unidentified-license (:licenses entry)))])))

(defn- render-vulnerabilities
  [data]
  (md-table ["Component" "Version" "Type" "Vulnerabilities"]
            (for [entry data]
              [(:name entry) (:version entry)
               (some-> (:component-type entry) name)
               (str/join "; " (map format-vulnerability-entry (:vulnerabilities entry)))])))

(defn- render-vulnerability-summary
  [data]
  (str (md-table ["Severity" "Count"]
                  (for [severity [:critical :high :medium :low :unknown]]
                    [(name severity) (str (get (:by-severity data) severity 0))]))
       "\n"
       "Affected components: " (:affected-components data) "\n"))

(defn- render-blocked-vulnerabilities
  [data]
  (md-table ["CVE" "Severity" "Affected" "Description"]
            (for [entry data]
              [(:id entry) (some-> (:severity entry) name)
               (str/join ", " (:affected entry))
               (or (:description entry) "")])))

(def ^:private report-headings
  "Markdown section heading per report key."
  {:licenses "Licenses"
   :license-summary "License Summary"
   :multi-licensed "Multi-licensed Components"
   :unidentified-licenses "Unidentified Licenses"
   :blacklisted-licenses "Blacklisted Licenses"
   :vulnerabilities "Vulnerabilities"
   :vulnerability-summary "Vulnerability Summary"
   :blocked-vulnerabilities "Blocked Vulnerabilities"})

(def ^:private report-renderers
  "Renderer function per report key."
  {:licenses render-licenses
   :license-summary render-license-summary
   :multi-licensed render-multi-licensed
   :unidentified-licenses render-unidentified-licenses
   :blacklisted-licenses render-licenses
   :vulnerabilities render-vulnerabilities
   :vulnerability-summary render-vulnerability-summary
   :blocked-vulnerabilities render-blocked-vulnerabilities})

(defn render-report
  "Renders `report-key`'s `data` as markdown. For `:all` (a map of report
   key to that report's data, as produced by the CLI's `:all` report),
   renders one heading and body per entry."
  [report-key data]
  (if (= :all report-key)
    (str/join "\n" (for [[key value] data]
                      (render-report key value)))
    (str "## " (get report-headings report-key (name report-key)) "\n\n"
         ((get report-renderers report-key pr-str) data)
         "\n")))

(defmethod template/render :markdown
  [_format report-key data]
  (render-report report-key data))
