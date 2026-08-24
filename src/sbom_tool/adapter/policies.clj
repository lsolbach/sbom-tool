(ns sbom-tool.adapter.policies
  (:require [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.spec.alpha :as s]
            [sbom-tool.application.repository :as repo]
            [sbom-tool.domain.license :as license]
            [sbom-tool.domain.vulnerability :as vulnerability]))

(defn- validate!
  "Throws an ex-info if `policy` does not conform to `spec`, naming `path`
   (or the bundled default policy, when `path` is nil) in the error."
  [spec policy path]
  (when-not (s/valid? spec policy)
    (throw (ex-info (str "Invalid policy file " (or path "(bundled default)") ":\n"
                         (s/explain-str spec policy))
                    {:sbom-tool/error-type :invalid-policy
                     :path path
                     :explain-data (s/explain-data spec policy)}))))

(defn- read-edn-file
  "Reads and parses the EDN file at `path` (or `resource`, when `path` is
   nil), tagging read/parse failures for
   `sbom-tool.adapter.ui.errors/friendly-message`."
  [path resource]
  (let [source (or path (str "bundled default (" resource ")"))]
    (try
      (edn/read-string (if path (slurp path) (slurp (io/resource resource))))
      (catch java.io.FileNotFoundException e
        (let [msg (str "file not found: " path)]
          (throw (ex-info msg
                           {:sbom-tool/error-type :policy-file-not-found :path source}
                           e))))
      (catch RuntimeException e
        (let [msg (str "malformed EDN: " (ex-message e))]
          (throw (ex-info msg
                           {:sbom-tool/error-type :malformed-policy-edn :path source}
                           e)))))))

(def default-license-policy-resource
  "Classpath location of the bundled default license policy."
  "policy/license-policy.edn")

(def default-vulnerability-policy-resource
  "Classpath location of the bundled default vulnerability policy."
  "policy/vulnerability-policy.edn")

(defn read-license-policy-file
  "Reads and parses the EDN license policy at `path`, falling back to the
   bundled default policy when `path` is not given. Throws an ex-info if
   the parsed policy does not conform to `sbom-tool.domain.license/policies`."
  [path]
  (let [policy (read-edn-file path default-license-policy-resource)]
    (validate! ::license/policies policy path)
    policy))

(defn read-vulnerability-policy-file
  "Reads and parses the EDN vulnerability policy at `path`, falling back to
   the bundled default policy when `path` is not given. Throws an ex-info
   if the parsed policy does not conform to
   `sbom-tool.domain.vulnerability/policy`."
  [path]
  (let [policy (read-edn-file path default-vulnerability-policy-resource)]
    (validate! ::vulnerability/policy policy path)
    policy))

(defmethod repo/read-policies :file
  [_options path]
  (->> path
       read-license-policy-file
       (swap! repo/state assoc :policies)))

(defmethod repo/read-vulnerability-policies :file
  [_options path]
  (->> path
       read-vulnerability-policy-file
       (swap! repo/state assoc :vulnerability-policies)))
