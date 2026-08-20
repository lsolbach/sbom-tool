(ns sbom-tool.domain.sbom
  (:require [clojure.string :as string]
            [clojure.spec.alpha :as s]))
  
  ;
  (s/def ::non-empty-string
    (s/and string? #(not (clojure.string/blank? %))))
  
  (s/def ::id ::non-empty-string)
  (s/def ::name ::non-empty-string)
  (s/def ::version string?)
  (s/def ::url string?)
  (s/def ::description string?)
  (s/def ::text string?)

  (s/def ::purl string?)
  (s/def ::cpe string?)
  (s/def ::spdx-id string?)
  (s/def ::bom-ref string?)
  
  (s/def ::identifiers
    (s/keys :opt [::purl
                  ::cpe
                  ::spdx-id
                  ::bom-ref]))
  
  (s/def ::hash-algorithm
    #{:md5
      :sha1
      :sha256
      :sha384
      :sha512
      :sha3-256
      :sha3-384
      :sha3-512
      :blake2b-256
      :blake2b-384
      :blake2b-512
      :blake3
      :adler32})
  
  (s/def ::algorithm ::hash-algorithm)
  (s/def ::value ::non-empty-string)
  
  (s/def ::hash
    (s/keys :req [::algorithm ::value]))
  
  (s/def ::hashes
    (s/coll-of ::hash :kind vector?))
  
(s/def ::license-id string?)
(s/def ::license-name string?)
(s/def ::license-text string?)
(s/def ::license-url string?)

(s/def ::license
  (s/keys :opt [::license-id
                ::license-name
                ::license-text
                ::license-url]))

(s/def ::declared
  (s/coll-of ::license :kind vector?))

(s/def ::concluded
  (s/coll-of ::license :kind vector?))

(s/def ::from-files
  (s/coll-of ::license :kind vector?))

(s/def ::licenses
  (s/keys :opt [::declared
                ::concluded
                ::from-files]))

(s/def ::reference-type
  #{:website
    :issue-tracker
    :vcs
    :advisory
    :distribution
    :documentation
    :other})

(s/def ::reference
  (s/keys :req [::url]
          :opt [::reference-type
                ::name]))

(s/def ::external-references
  (s/coll-of ::reference :kind vector?))

(s/def ::component-type
  #{:application
    :framework
    :library
    :container
    :operating-system
    :device
    :file
    :firmware
    :other})

(s/def ::supplier ::name)
(s/def ::manufacturer ::name)
(s/def ::copyright string?)

(s/def ::properties
  (s/map-of string? any?))

(s/def ::component
  (s/keys
   :req [::id
         ::name]
   :opt [::version
         ::component-type
         ::supplier
         ::manufacturer
         ::identifiers
         ::hashes
         ::licenses
         ::description
         ::copyright
         ::external-references
         ::properties]))

(s/def ::relationship-type
  #{:depends-on
    :dependency-of
    :contains
    :contained-by
    :build-tool
    :dev-dependency
    :optional-dependency
    :provided-by
    :other})

(s/def ::from ::id)
(s/def ::to ::id)

(s/def ::relationship
  (s/keys :req [::from
                ::to
                ::relationship-type]))

(s/def ::relationships
  (s/coll-of ::relationship :kind vector?))

(s/def ::severity
  #{:unknown
    :low
    :medium
    :high
    :critical})

(s/def ::source
  (s/keys :opt [::name ::url]))

(s/def ::affected
  (s/coll-of ::id :kind vector?))

(s/def ::references
  (s/coll-of ::non-empty-string :kind vector?))

(s/def ::vulnerability
  (s/keys :req [::id]
          :opt [::source
                ::severity
                ::description
                ::references
                ::affected
                ::properties]))

(s/def ::vulnerabilities
  (s/coll-of ::vulnerability :kind vector?))

(s/def ::format
  #{:cyclonedx :spdx})

(s/def ::format-version
  ::version)

(s/def ::creator
  (s/or :string string?
        :map (s/keys :req [::name])))

(s/def ::created string?)

(s/def ::bom-metadata
  (s/keys
   :opt [::id
         ::format
         ::format-version
         ::created
         ::creator]))

(s/def ::components
  (s/coll-of ::component :kind vector?))

(s/def ::sbom
  (s/keys
   :req [::components]
   :opt [::bom-metadata
         ::relationships
         ::vulnerabilities
         ::properties]))

