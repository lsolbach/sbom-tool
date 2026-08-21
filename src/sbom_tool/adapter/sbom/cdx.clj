(ns sbom-tool.adapter.sbom.cdx
  (:require [cheshire.core :as json]
            [babashka.fs :as fs]
            [sbom-tool.application.repository :as repo]
            [sbom-tool.domain.sbom :as sbom]))

(defn cdx-files
  "Returns the list of CycloneDX files in the path."
  [path]
  (->> (fs/glob path "**{.cdx.json}")
       (map str)))

(defn read-json
  "Returns the data of the JSON file with the given `filename`."
  [filename]
  (-> filename
      (slurp)
      (json/parse-string keyword)))

(def ^:private hash-algorithms
  "Maps CycloneDX hash algorithm names to canonical hash algorithms."
  {"MD5" :md5
   "SHA-1" :sha1
   "SHA-256" :sha256
   "SHA-384" :sha384
   "SHA-512" :sha512
   "SHA3-256" :sha3-256
   "SHA3-384" :sha3-384
   "SHA3-512" :sha3-512})

(def ^:private component-types
  "Maps CycloneDX component types to canonical component types."
  {"application" :application
   "framework" :framework
   "library" :library
   "container" :container
   "platform" :operating-system
   "operating-system" :operating-system
   "device" :device
   "device-driver" :device
   "firmware" :firmware
   "file" :file})

(def ^:private reference-types
  "Maps CycloneDX external reference types to canonical reference types."
  {"website" :website
   "issue-tracker" :issue-tracker
   "vcs" :vcs
   "advisories" :advisory
   "distribution" :distribution
   "distribution-intake" :distribution
   "documentation" :documentation})

(def ^:private severities
  "Maps CycloneDX vulnerability rating severities to canonical severities."
  {"critical" :critical
   "high" :high
   "medium" :medium
   "low" :low
   "info" :unknown
   "none" :unknown
   "unknown" :unknown})

(defn- remove-nils
  "Removes the entries with a nil value from map `m`."
  [m]
  (into {} (remove (comp nil? val)) m))

(defn- party-name
  "Returns the name of a CycloneDX organizational entity/contact `party`,
   which may be given as a plain string or as a map with a `:name` key."
  [party]
  (cond
    (string? party) party
    (map? party) (:name party)))

(defn map-hash
  "Maps a CycloneDX hash object to the canonical hash model."
  [{:keys [alg content]}]
  (when-let [algorithm (hash-algorithms alg)]
    {::sbom/algorithm algorithm
     ::sbom/value content}))

(defn map-hashes
  "Maps the CycloneDX `hashes` array to the canonical hashes model."
  [hashes]
  (not-empty (into [] (keep map-hash) hashes)))

(defn map-license
  "Maps a CycloneDX LicenseChoice (either a `:license` object or a license
   `:expression`) to the canonical license model. An `:expression` is a
   formal SPDX license expression per the CycloneDX schema, so it is
   mapped to `::license-id`, same as a plain SPDX license id, rather than
   to the free-text `::license-name`."
  [{:keys [license expression]}]
  (cond
    license (remove-nils {::sbom/license-id (:id license)
                           ::sbom/license-name (:name license)
                           ::sbom/license-text (get-in license [:text :content])
                           ::sbom/license-url (:url license)})
    expression {::sbom/license-id expression}))

(defn map-licenses
  "Maps the CycloneDX `licenses` array to the canonical licenses model.
   CycloneDX does not distinguish declared/concluded/from-files licenses,
   so all licenses are reported as declared."
  [licenses]
  (when-let [licenses (not-empty (into [] (keep map-license) licenses))]
    {::sbom/declared licenses}))

(defn map-external-reference
  "Maps a CycloneDX external reference to the canonical reference model."
  [{:keys [url type comment]}]
  (remove-nils {::sbom/url url
                ::sbom/reference-type (get reference-types type :other)
                ::sbom/name comment}))

(defn map-external-references
  "Maps the CycloneDX `externalReferences` array to the canonical model."
  [external-references]
  (not-empty (into [] (map map-external-reference) external-references)))

(defn map-identifiers
  "Maps the identifying fields of a CycloneDX component to the canonical
   identifiers model."
  [{:keys [purl cpe bom-ref]}]
  (not-empty (remove-nils {::sbom/purl purl
                            ::sbom/cpe cpe
                            ::sbom/bom-ref bom-ref})))

(defn map-properties
  "Maps the CycloneDX `properties` array to the canonical properties model."
  [properties]
  (not-empty (into {} (map (juxt :name :value)) properties)))

(defn component-id
  "Returns an identifier for a CycloneDX `component`, preferring the
   `bom-ref`, falling back to the `purl` and finally `name`/`version`."
  [{:keys [bom-ref purl name version]}]
  (or bom-ref purl (str name (when version (str "@" version)))))

(defn map-component
  "Maps a CycloneDX component to the canonical component model."
  [{:keys [name version type supplier manufacturer description copyright
           hashes licenses properties]
    external-references :externalReferences
    :as component}]
  (remove-nils
   {::sbom/id (component-id component)
    ::sbom/name name
    ::sbom/version version
    ::sbom/component-type (get component-types type :other)
    ::sbom/supplier (party-name supplier)
    ::sbom/manufacturer (party-name manufacturer)
    ::sbom/identifiers (map-identifiers component)
    ::sbom/hashes (map-hashes hashes)
    ::sbom/licenses (map-licenses licenses)
    ::sbom/description description
    ::sbom/copyright copyright
    ::sbom/external-references (map-external-references external-references)
    ::sbom/properties (map-properties properties)}))

(defn map-components
  "Maps the CycloneDX `components` array to the canonical components model."
  [components]
  (into [] (map map-component) components))

(defn map-dependency
  "Maps a CycloneDX dependency entry to canonical `depends-on` relationships,
   one per referenced dependency."
  [{:keys [ref] dependencies :dependsOn}]
  (for [to dependencies]
    {::sbom/from ref
     ::sbom/to to
     ::sbom/relationship-type :depends-on}))

(defn map-relationships
  "Maps the CycloneDX `dependencies` array to the canonical relationships model."
  [dependencies]
  (not-empty (into [] (mapcat map-dependency) dependencies)))

(defn map-severity
  "Returns the canonical severity for the first rated severity found in
   the CycloneDX vulnerability `ratings`."
  [ratings]
  (when-let [severity (some :severity ratings)]
    (get severities severity :unknown)))

(defn map-vulnerability-source
  "Maps a CycloneDX vulnerability source to the canonical source model."
  [{:keys [name url]}]
  (not-empty (remove-nils {::sbom/name name ::sbom/url url})))

(defn map-affected
  "Maps the CycloneDX vulnerability `affects` array to the ids of the
   affected components."
  [affects]
  (not-empty (into [] (keep :ref) affects)))

(defn map-vulnerability
  "Maps a CycloneDX vulnerability to the canonical vulnerability model."
  [{:keys [id source description ratings affects properties]}]
  (remove-nils
   {::sbom/id id
    ::sbom/source (map-vulnerability-source source)
    ::sbom/severity (map-severity ratings)
    ::sbom/description description
    ::sbom/affected (map-affected affects)
    ::sbom/properties (map-properties properties)}))

(defn map-vulnerabilities
  "Maps the CycloneDX `vulnerabilities` array to the canonical model."
  [vulnerabilities]
  (into [] (map map-vulnerability) vulnerabilities))

(defn map-creator
  "Returns the name of the creator of the SBOM from the CycloneDX `metadata`,
   preferring the first author, then the manufacturer/manufacture entity."
  [{:keys [authors manufacturer manufacture]}]
  (or (:name (first authors))
      (party-name manufacturer)
      (party-name manufacture)))

(defn map-bom-metadata
  "Maps the CycloneDX BOM header fields to the canonical bom-metadata model."
  [{:keys [metadata] serial-number :serialNumber spec-version :specVersion}]
  (not-empty
   (remove-nils
    {::sbom/id serial-number
     ::sbom/format :cyclonedx
     ::sbom/format-version spec-version
     ::sbom/created (:timestamp metadata)
     ::sbom/creator (map-creator metadata)})))

(defn cdx->sbom
  "Maps a parsed CycloneDX BOM document to the canonical SBOM model."
  [bom]
  (remove-nils
   {::sbom/components (map-components (:components bom))
    ::sbom/bom-metadata (map-bom-metadata bom)
    ::sbom/relationships (map-relationships (:dependencies bom))
    ::sbom/vulnerabilities (not-empty (map-vulnerabilities (:vulnerabilities bom)))}))

(defmethod repo/read-sboms :cdx
  [_options path]
  (->> (cdx-files path)
       (map read-json)
       (map cdx->sbom)
       (into [])
       (swap! repo/state update :sboms (fnil into []))))
