(ns sbom-tool.adapter.spdx.file-repository
  (:require [cheshire.core :as json]
            [clojure.string :as string]
            [babashka.fs :as fs]
            [sbom-tool.application.repository :as repo]
            [sbom-tool.domain.sbom :as sbom]))

(defn spdx-files
  "Returns the list of SPDX JSON files in the path."
  [path]
  (->> (fs/glob path "**{.spdx.json}")
       (map str)))

(defn read-json
  "Returns the data of the JSON file with the given `filename`."
  [filename]
  (-> filename
      (slurp)
      (json/parse-string keyword)))

(def ^:private not-asserted?
  "SPDX placeholder values meaning \"no value was asserted\"."
  #{"NOASSERTION" "NONE" nil ""})

(defn- asserted
  "Returns `value` unless it is an SPDX NOASSERTION/NONE placeholder."
  [value]
  (when-not (not-asserted? value)
    value))

(def ^:private hash-algorithms
  "Maps SPDX checksum algorithm names to canonical hash algorithms."
  {"MD5" :md5
   "SHA1" :sha1
   "SHA256" :sha256
   "SHA384" :sha384
   "SHA512" :sha512
   "SHA3-256" :sha3-256
   "SHA3-384" :sha3-384
   "SHA3-512" :sha3-512
   "BLAKE2b-256" :blake2b-256
   "BLAKE2b-384" :blake2b-384
   "BLAKE2b-512" :blake2b-512
   "BLAKE3" :blake3
   "ADLER32" :adler32})

(def ^:private component-types
  "Maps SPDX `primaryPackagePurpose` values to canonical component types."
  {"APPLICATION" :application
   "FRAMEWORK" :framework
   "LIBRARY" :library
   "CONTAINER" :container
   "OPERATING-SYSTEM" :operating-system
   "DEVICE" :device
   "FIRMWARE" :firmware
   "FILE" :file})

(def ^:private relationship-types
  "Maps SPDX relationship types to canonical relationship types."
  {"DEPENDS_ON" :depends-on
   "DEPENDENCY_OF" :dependency-of
   "CONTAINS" :contains
   "CONTAINED_BY" :contained-by
   "BUILD_DEPENDENCY_OF" :build-tool
   "BUILD_TOOL_OF" :build-tool
   "DEV_DEPENDENCY_OF" :dev-dependency
   "DEV_TOOL_OF" :dev-dependency
   "OPTIONAL_DEPENDENCY_OF" :optional-dependency
   "PROVIDED_DEPENDENCY_OF" :provided-by})

(def ^:private ref-type->identifier-key
  "Maps SPDX external reference types to canonical identifier keys."
  {"purl" ::sbom/purl
   "cpe23type" ::sbom/cpe
   "cpe22type" ::sbom/cpe})

(def ^:private ref-type->reference-type
  "Maps SPDX SECURITY category external reference types (Annex F) to
   canonical reference types."
  {"advisory" :advisory})

(defn- remove-nils
  "Removes the entries with a nil value from map `m`."
  [m]
  (into {} (remove (comp nil? val)) m))

(defn- entity-name
  "Returns the name portion of an SPDX entity string such as
   `\"Organization: ACME Corp (info@acme.org)\"`, or nil if the entity is
   `NOASSERTION`/`NONE`/absent."
  [entity]
  (when-let [entity (asserted entity)]
    (-> entity
        (string/replace #"^(Organization|Person|Tool):\s*" "")
        (string/replace #"\s*\([^)]*\)\s*$" "")
        string/trim
        not-empty)))

(defn map-checksum
  "Maps an SPDX checksum object to the canonical hash model."
  [{:keys [algorithm checksumValue]}]
  (when-let [algorithm (hash-algorithms algorithm)]
    {::sbom/algorithm algorithm
     ::sbom/value checksumValue}))

(defn map-checksums
  "Maps the SPDX package `checksums` array to the canonical hashes model."
  [checksums]
  (not-empty (into [] (keep map-checksum) checksums)))

(defn map-license
  "Maps an SPDX license expression string to a canonical license, or nil if
   it is not asserted."
  [expression]
  (when-let [expression (asserted expression)]
    {::sbom/license-id expression}))

(defn map-licenses
  "Maps a package's `licenseConcluded`/`licenseDeclared`/
   `licenseInfoFromFiles` fields to the canonical licenses model."
  [{:keys [licenseConcluded licenseDeclared licenseInfoFromFiles]}]
  (not-empty
   (remove-nils
    {::sbom/concluded (some-> (map-license licenseConcluded) vector)
     ::sbom/declared (some-> (map-license licenseDeclared) vector)
     ::sbom/from-files (not-empty (into [] (keep map-license) licenseInfoFromFiles))})))

(defn map-identifiers
  "Maps the SPDXID and purl/cpe external references of an SPDX package to
   the canonical identifiers model."
  [{:keys [SPDXID externalRefs]}]
  (let [identifiers (keep (fn [{:keys [referenceType referenceLocator]}]
                             (when-let [k (ref-type->identifier-key
                                           (string/lower-case (or referenceType "")))]
                               [k referenceLocator]))
                           externalRefs)]
    (not-empty (into {::sbom/bom-ref SPDXID} identifiers))))

(defn map-external-reference
  "Maps an SPDX externalRef that is not a purl/cpe identifier to the
   canonical reference model."
  [{:keys [referenceType referenceLocator]}]
  (when-let [url (asserted referenceLocator)]
    {::sbom/url url
     ::sbom/reference-type (get ref-type->reference-type
                                 (string/lower-case (or referenceType ""))
                                 :other)
     ::sbom/name referenceType}))

(defn map-external-references
  "Maps a package's `externalRefs`, `homepage` and `downloadLocation` to the
   canonical external references model."
  [{:keys [externalRefs homepage downloadLocation]}]
  (let [other-refs (remove #(ref-type->identifier-key
                              (string/lower-case (or (:referenceType %) "")))
                           externalRefs)
        website (when-let [homepage (asserted homepage)]
                  {::sbom/url homepage ::sbom/reference-type :website})
        distribution (when-let [download (asserted downloadLocation)]
                       {::sbom/url download ::sbom/reference-type :distribution})]
    (not-empty (into [] (remove nil?)
                      (concat [website distribution] (map map-external-reference other-refs))))))

(defn map-component
  "Maps an SPDX package to the canonical component model."
  [{:keys [SPDXID name versionInfo description summary supplier originator
           copyrightText checksums primaryPackagePurpose]
    :as package}]
  (remove-nils
   {::sbom/id SPDXID
    ::sbom/name name
    ::sbom/version (asserted versionInfo)
    ::sbom/component-type (get component-types primaryPackagePurpose :other)
    ::sbom/supplier (entity-name supplier)
    ::sbom/manufacturer (entity-name originator)
    ::sbom/identifiers (map-identifiers package)
    ::sbom/hashes (map-checksums checksums)
    ::sbom/licenses (map-licenses package)
    ::sbom/description (asserted (or description summary))
    ::sbom/copyright (asserted copyrightText)
    ::sbom/external-references (map-external-references package)}))

(defn map-components
  "Maps the SPDX `packages` array to the canonical components model."
  [packages]
  (into [] (map map-component) packages))

(defn map-relationship
  "Maps an SPDX relationship to the canonical relationship model."
  [{:keys [spdxElementId relatedSpdxElement relationshipType]}]
  {::sbom/from spdxElementId
   ::sbom/to relatedSpdxElement
   ::sbom/relationship-type (get relationship-types relationshipType :other)})

(defn map-relationships
  "Maps the SPDX `relationships` array to the canonical relationships model."
  [relationships]
  (not-empty (into [] (map map-relationship) relationships)))

(defn map-creator
  "Returns the name of the creator of the SBOM from the SPDX `creators`
   list, preferring an Organization, then a Person, then a Tool entry."
  [creators]
  (let [by-prefix (fn [prefix]
                     (some #(when (string/starts-with? % prefix) (entity-name %))
                           creators))]
    (or (by-prefix "Organization:")
        (by-prefix "Person:")
        (by-prefix "Tool:")
        (some-> (first creators) entity-name))))

(defn map-format-version
  "Strips the `SPDX-` prefix from an SPDX spec version, e.g. `SPDX-2.2`."
  [spdx-version]
  (some-> spdx-version (string/replace #"^SPDX-" "")))

(defn map-bom-metadata
  "Maps the SPDX document header fields to the canonical bom-metadata model."
  [{:keys [SPDXID documentNamespace spdxVersion creationInfo]}]
  (not-empty
   (remove-nils
    {::sbom/id (or SPDXID documentNamespace)
     ::sbom/format :spdx
     ::sbom/format-version (map-format-version spdxVersion)
     ::sbom/created (:created creationInfo)
     ::sbom/creator (map-creator (:creators creationInfo))})))

(defn spdx->sbom
  "Maps a parsed SPDX document to the canonical SBOM model."
  [document]
  (remove-nils
   {::sbom/components (map-components (:packages document))
    ::sbom/bom-metadata (map-bom-metadata document)
    ::sbom/relationships (map-relationships (:relationships document))}))

(defmethod repo/read-sboms :spdx
  [_options path]
  (->> (spdx-files path)
       (map read-json)
       (map spdx->sbom)
       (into [])
       (swap! repo/state update :sboms (fnil into []))))
