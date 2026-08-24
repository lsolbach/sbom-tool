(ns sbom-tool.adapter.ui.errors
  "Formats exceptions raised while reading SBOMs/policies or rendering
   reports into short, human-readable CLI messages."
  (:require [clojure.string :as string]))

(def runtime-error-exit-code
  "Process exit code for a runtime/data error (as opposed to a CLI usage
   error or a policy violation, both of which exit with status 1)."
  2)

(defmulti friendly-message
  "Returns a human-readable message for `ex`, dispatching on its
   `:sbom-tool/error-type` (via `ex-data`), or `::unknown` if `ex` carries
   no such tag."
  (fn [ex] (:sbom-tool/error-type (ex-data ex) ::unknown)))

(defmethod friendly-message :policy-file-not-found
  [ex]
  (str "Could not read the policy file " (:path (ex-data ex)) ": " (ex-message ex)))

(defmethod friendly-message :malformed-policy-edn
  [ex]
  (str "The policy file " (:path (ex-data ex)) " is not valid EDN: " (ex-message ex)))

(defmethod friendly-message :invalid-policy
  ;; the message already comes from `sbom-tool.adapter.policies/validate!`
  ;; via `s/explain-str`, which is already human-readable
  [ex]
  (ex-message ex))

(defmethod friendly-message :sbom-file-not-found
  [ex]
  (str "Could not read the SBOM file " (:path (ex-data ex)) ": " (ex-message ex)))

(defmethod friendly-message :malformed-sbom-json
  [ex]
  (str "The SBOM file " (:path (ex-data ex)) " is not valid JSON: " (ex-message ex)))

(defmethod friendly-message :report-rendering-failed
  [ex]
  (str "Could not render the report: " (ex-message ex)))

(defmethod friendly-message ::unknown
  [ex]
  (str "An unexpected error occurred: " (ex-message ex)))

(defn debug-details
  "Returns the full cause chain of `ex` as a string, for `--debug`."
  [ex]
  (->> (iterate ex-cause ex)
       (take-while some?)
       (map #(str (.getName (class %)) ": " (ex-message %)))
       (string/join "\nCaused by: ")))
