(ns sbom-tool.adapter.policy.file-repository
  (:require [clojure.edn :as edn]
            [clojure.java.io :as io]
            [sbom-tool.application.repository :as repo]))

(def default-policy-resource
  "Classpath location of the bundled default license policy."
  "policy/license-policy.edn")

(def default-vulnerability-policy-resource
  "Classpath location of the bundled default vulnerability policy."
  "policy/vulnerability-policy.edn")

(defn read-policy-file
  "Reads and parses the EDN license policy at `path`, falling back to the
   bundled default policy when `path` is not given."
  [path]
  (-> (if path
        (slurp path)
        (slurp (io/resource default-policy-resource)))
      (edn/read-string)))

(defn read-vulnerability-policy-file
  "Reads and parses the EDN vulnerability policy at `path`, falling back to
   the bundled default policy when `path` is not given."
  [path]
  (-> (if path
        (slurp path)
        (slurp (io/resource default-vulnerability-policy-resource)))
      (edn/read-string)))

(defmethod repo/read-policies :file
  [_options path]
  (->> path
       read-policy-file
       (swap! repo/state assoc :policies)))

(defmethod repo/read-vulnerability-policies :file
  [_options path]
  (->> path
       read-vulnerability-policy-file
       (swap! repo/state assoc :vulnerability-policies)))
