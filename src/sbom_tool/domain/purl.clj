(ns sbom-tool.domain.purl
  "Pure domain logic for parsing and rendering purls (Package URLs), the
   `pkg:type/namespace/name@version?qualifiers#subpath` component
   identifier format used by `::sbom/purl`. Every vulnerability-database
   adapter that needs a purl's decomposed parts (rather than treating it
   as an opaque string, as `domain/component.clj` and `application/
   repository.clj` do) shares this single implementation."
  (:require [clojure.string :as string])
  (:import [java.net URLDecoder]))

(defn- decode
  [s]
  (URLDecoder/decode s "UTF-8"))

(defn parse-purl
  "Parses a `pkg:type/namespace/name@version` purl string into
   `{:type :namespace :name :version}` (`:namespace` nil when the purl
   carries none), discarding any `?qualifiers`/`#subpath` suffix.
   Returns nil if `purl` is not a well-formed, versioned purl (missing
   the `pkg:` scheme, a name, or a version) -- an unversioned purl is
   exactly as unusable to a version-keyed vulnerability lookup as a
   non-purl string."
  [purl]
  (when (and purl (string/starts-with? purl "pkg:"))
    (let [body (-> (subs purl 4)
                    (string/replace #"#.*$" "")
                    (string/replace #"\?.*$" ""))
          at (string/last-index-of body \@)]
      (when (and at (< (inc at) (count body)))
        (let [type-and-name (subs body 0 at)
              version (subs body (inc at))
              segments (string/split type-and-name #"/")]
          (when (>= (count segments) 2)
            (let [namespace-segments (subvec (vec segments) 1 (dec (count segments)))]
              {:type (decode (first segments))
               :namespace (when (seq namespace-segments)
                            (string/join "/" (map decode namespace-segments)))
               :name (decode (last segments))
               :version (decode version)})))))))

(defn qualified-name
  "Returns the single-string package name for a parsed purl `{:type
   :namespace :name}`, joining `:namespace` and `:name` the way each
   ecosystem expects: `:` for Maven's `group:artifact`, `/` for
   everything else that carries a namespace (npm scoped packages, Go
   import paths), or the bare `:name` when there is no namespace at
   all."
  [{:keys [type namespace name]}]
  (cond
    (nil? namespace) name
    (= "maven" type) (str namespace ":" name)
    :else (str namespace "/" name)))
