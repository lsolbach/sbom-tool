(ns sbom-tool.adapter.report.markdown
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
  {:white "ok" :black "blacklisted" :grey "review"
   :proprietary "proprietary" :no-license "no license" :reviewed "reviewed"})

(defn- format-license-name
  "Formats a license entry's display name for a markdown cell: its
   `:license-name` (falling back to `:license-id` when unresolved) as a
   link to `:license-url` when known, plain text otherwise."
  [entry]
  (let [label (or (:license-name entry) (:license-id entry))]
    (if-let [url (:license-url entry)]
      (str "[" label "](" url ")")
      label)))

(defn- status-label
  "Formats a license policy `status` keyword (`:white`/`:black`/`:grey`)
   as its human-readable label, or nil if `status` is nil (no license at
   all, e.g. a component with no licenses)."
  [status]
  (when status (get license-status-label status (name status))))

(def ^:private vulnerability-status-label
  {:ok "ok" :blocked "blocked" :accepted "accepted"})

(def ^:private cve-id-pattern
  #"(?i)^CVE-\d{4}-\d{4,}$")

(defn- format-vulnerability-id
  "Renders `id` as a markdown link to its CVE record on opencve.io if `id`
   looks like a CVE id (e.g. \"CVE-2026-71038\"), otherwise returns `id` as-is."
  [id]
  (if (re-matches cve-id-pattern id)
    (str "[" id "](https://app.opencve.io/cve/" id ")")
    id))

(defn- format-vulnerability-entry
  [{:keys [id severity status]}]
  (str (format-vulnerability-id id) " (" (name severity) ", " (get vulnerability-status-label status (name status)) ")"))

(defn- format-choice-cell
  "Formats one column's value across a license choice (a set of
   `license/license-entry`s that must be satisfied together, see
   `sbom-tool.application.report/multi-licensed`) by applying `value-fn`
   to each entry and joining them with \"AND\", e.g. \"MIT\" for a
   single-entry choice or \"Apache-2.0 AND CC0-1.0\" for a two-entry one."
  [choice value-fn]
  (str/join " AND " (map value-fn (sort-by :license-id choice))))

(defn- format-sources
  "Formats the source document formats (see `:sources` on a report entry)
   as e.g. \"cyclonedx, spdx\"."
  [sources]
  (str/join ", " (map name sources)))

(defn- render-licenses
  "Renders one row per component per license -- or, for a component with
   no licenses at all, a single row with blank license columns, so it
   isn't dropped from the report."
  [data]
  (md-table ["Component" "Version" "Type" "License ID" "License Name" "Status" "Sources"]
            (for [entry data
                  license (or (seq (:licenses entry)) [nil])]
              [(:name entry) (:version entry)
               (some-> (:component-type entry) name)
               (:license-id license)
               (format-license-name license)
               (status-label (:status license))
               (format-sources (:sources entry))])))

(defn- render-license-status-summary
  [data]
  (md-table ["Status" "Count"]
            (for [status [:white :grey :black :proprietary :no-license :reviewed]]
              [(name status) (str (get data status 0))])))

(defn- render-license-summary
  [data]
  (md-table ["License" "Count"]
            (->> data
                 (sort-by (juxt (comp - val) key))
                 (map (fn [[license count]] [license (str count)])))))

(defn- render-multi-licensed
  "Renders one row per component per license choice -- the disjunctive
   (OR) alternatives a component offers -- with each column joining that
   choice's conjunctive (AND) entries."
  [data]
  (md-table ["Component" "Version" "License ID" "License Name" "Status" "Sources"]
            (for [entry data
                  choice (:licenses entry)]
              [(:name entry) (:version entry)
               (format-choice-cell choice :license-id)
               (format-choice-cell choice format-license-name)
               (format-choice-cell choice (comp status-label :status))
               (format-sources (:sources entry))])))

(defn- render-unidentified-licenses
  "Renders one row per component per unidentified license -- or, for a
   component with no licenses at all, a single row with blank license
   columns, so it isn't dropped from the report."
  [data]
  (md-table ["Component" "Version" "Reason" "License ID" "License Name" "Status" "URL" "Sources"]
            (for [entry data
                  license (or (seq (:licenses entry)) [nil])]
              [(:name entry) (:version entry)
               (case (:reason entry)
                 :no-license "no license"
                 :unidentified-license "unidentified license"
                 :proprietary "proprietary"
                 :reviewed "reviewed"
                 (name (:reason entry)))
               (:license-id license)
               (format-license-name license)
               (status-label (:status license))
               (:url license)
               (format-sources (:sources entry))])))

(defn- render-vulnerabilities
  [data]
  (md-table ["Component" "Version" "Type" "Vulnerabilities" "Sources"]
            (for [entry data]
              [(:name entry) (:version entry)
               (some-> (:component-type entry) name)
               (str/join "; " (map format-vulnerability-entry (:vulnerabilities entry)))
               (format-sources (:sources entry))])))

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
              [(format-vulnerability-id (:id entry)) (some-> (:severity entry) name)
               (str/join ", " (:affected entry))
               (or (:description entry) "")])))

(def ^:private report-headings
  "Markdown section heading per report key."
  {:licenses "Licenses"
   :license-status-summary "License Status Summary"
   :license-summary "License Summary"
   :multi-licensed "Multi-licensed Components"
   :unidentified-licenses "Unidentified Licenses"
   :blacklisted-licenses "Blacklisted Licenses Used"
   :vulnerabilities "Vulnerabilities"
   :vulnerability-summary "Vulnerability Summary"
   :blocked-vulnerabilities "Blocked Vulnerabilities"})

(def ^:private report-renderers
  "Renderer function per report key."
  {:licenses render-licenses
   :license-status-summary render-license-status-summary
   :license-summary render-license-summary
   :multi-licensed render-multi-licensed
   :unidentified-licenses render-unidentified-licenses
   :blacklisted-licenses render-licenses
   :vulnerabilities render-vulnerabilities
   :vulnerability-summary render-vulnerability-summary
   :blocked-vulnerabilities render-blocked-vulnerabilities})

(def ^:private bundle-report-keys
  "Report keys whose data is a map of report key to that report's data, as
   produced by the CLI's `:all`, `:all-license` and `:all-vulnerabilities`
   reports."
  #{:all :all-license :all-vulnerabilities})

(defn render-report
  "Renders `report-key`'s `data` as markdown. For a bundle report key (see
   `bundle-report-keys`), renders one heading and body per entry."
  [report-key data]
  (if (contains? bundle-report-keys report-key)
    (str/join "\n" (for [[key value] data]
                      (render-report key value)))
    (str "## " (get report-headings report-key (name report-key)) "\n\n"
         ((get report-renderers report-key pr-str) data)
         "\n")))

(defmethod template/render :markdown
  [_format report-key data]
  (render-report report-key data))
