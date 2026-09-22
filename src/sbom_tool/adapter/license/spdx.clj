(ns sbom-tool.adapter.license.spdx
  "Adapter for the official SPDX license list
   (https://github.com/spdx/license-list-data), used to enrich license
   report entries with their SPDX-canonical name."
  (:require [cheshire.core :as json]
            [clojure.java.io :as io]))

(def default-resource
  "Classpath location of the bundled default SPDX license list snapshot."
  "spdx/licenses.json")

(def ^:private json-processing-exception-class
  "Resolved via `Class/forName` rather than referenced as a `catch` class
   literal, so this namespace also loads under babashka: its SCI
   interpreter cannot resolve `com.fasterxml.jackson.core.
   JsonProcessingException` as a catch clause at analysis time, even
   though the class itself is present at runtime (babashka's `cheshire`
   is backed by real Jackson)."
  (Class/forName "com.fasterxml.jackson.core.JsonProcessingException"))

(defn- map-license-entry
  "Maps one entry of the SPDX license list JSON to a `[id info]` pair,
   `info` being the subset of fields this tool uses."
  [{:keys [licenseId name isDeprecatedLicenseId isOsiApproved reference]}]
  [licenseId {:name name
              :license-url reference
              :deprecated? (boolean isDeprecatedLicenseId)
              :osi-approved? (boolean isOsiApproved)}])

(defn read-license-list
  "Reads and parses the SPDX license list JSON at `path` (the format
   published as `json/licenses.json` in spdx/license-list-data), falling
   back to the bundled default snapshot when `path` is nil. Returns a map
   of license id to `{:name :deprecated? :osi-approved?}`."
  [path]
  (try
    (let [source (if path (slurp path) (slurp (io/resource default-resource)))]
      (->> (json/parse-string source true)
           :licenses
           (into {} (map map-license-entry))))
    (catch java.io.FileNotFoundException e
      (let [msg (str "file not found: " path)]
        (throw (ex-info msg
                         {:sbom-tool/error-type :spdx-license-list-not-found :path path}
                         e))))
    (catch Exception e
      (if (instance? json-processing-exception-class e)
        (let [msg (str "malformed JSON: " (ex-message e))]
          (throw (ex-info msg
                           {:sbom-tool/error-type :malformed-spdx-license-list :path path}
                           e)))
        (throw e)))))
