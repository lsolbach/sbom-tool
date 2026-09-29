(ns sbom-tool.domain.vex
  "Pure domain logic for VEX (Vulnerability Exploitability eXchange) statements:
   a supplier's per-product assertion of whether a given vulnerability actually
   affects a product, used to overlay/annotate vulnerability reports (see
   `sbom-tool.domain.vulnerability`) independently of any single SBOM document --
   the same reasoning that keeps policy specs in `sbom-tool.domain.license`/
   `sbom-tool.domain.vulnerability` rather than `sbom-tool.domain.sbom`."
  (:require [clojure.spec.alpha :as s]
            [clojure.string :as string]
            [sbom-tool.domain.sbom :as sbom]))

(s/def ::vulnerability-id ::sbom/id)
(s/def ::aliases (s/coll-of string? :kind vector?))

(s/def ::status
  #{:affected :not-affected :fixed :under-investigation})

(s/def ::justification
  #{:component-not-present
    :vulnerable-code-not-present
    :vulnerable-code-not-in-execute-path
    :vulnerable-code-cannot-be-controlled-by-adversary
    :inline-mitigations-already-exist})

(s/def ::status-notes string?)
(s/def ::purls (s/coll-of string? :kind set?))
(s/def ::cpes (s/coll-of string? :kind set?))

(s/def ::statement
  (s/keys :req-un [::vulnerability-id ::status]
          :opt-un [::aliases ::justification ::status-notes ::purls ::cpes]))

(s/def ::statements
  (s/coll-of ::statement :kind vector?))

(defn- id-matches?
  "Returns true if `vulnerability-id` equals `statement`'s own id or one of its
   `:aliases`, case-insensitively -- CVE/GHSA ids are conventionally upper-cased
   but not guaranteed to be typed that way."
  [statement vulnerability-id]
  (some #(= (string/upper-case %) (string/upper-case vulnerability-id))
        (cons (:vulnerability-id statement) (:aliases statement))))

(defn- product-matches?
  "Returns true if `statement`'s `:purls`/`:cpes` intersects `component`'s own
   identifiers -- purl checked first, then cpe, the same preference
   `sbom-tool.domain.component/component-identity` already applies, since purl is
   the stronger, ecosystem-qualified signal."
  [statement component]
  (let [purl (get-in component [::sbom/identifiers ::sbom/purl])
        cpe (get-in component [::sbom/identifiers ::sbom/cpe])]
    (or (and purl (contains? (:purls statement) purl))
        (and cpe (contains? (:cpes statement) cpe)))))

(defn matching-statements
  "Returns the `statements` that apply to `component` and `vulnerability-id`:
   those whose id/aliases match `vulnerability-id` and whose product identifiers
   (`:purls`/`:cpes`) intersect `component`'s own `::sbom/identifiers`."
  [statements component vulnerability-id]
  (filterv #(and (id-matches? % vulnerability-id) (product-matches? % component))
           statements))

(def ^:private status-precedence
  "Resolution order when more than one statement matches the same
   component+vulnerability (e.g. two suppliers' documents): the most
   conservative status always wins, so one stale/overly-optimistic
   `:not-affected` statement can never suppress another document's genuine
   `:affected` claim -- ambiguity favors safety, not convenience."
  [:affected :under-investigation :fixed :not-affected])

(defn vex-entry
  "Returns the effective VEX status for `component`/`vulnerability-id` given
   `statements`: `{:status :justification :notes}` (the latter two omitted when
   absent), resolved via `status-precedence` when more than one statement
   matches, or nil when none do."
  [statements component vulnerability-id]
  (when-let [matches (not-empty (matching-statements statements component vulnerability-id))]
    (let [statuses (into #{} (map :status) matches)
          status (first (filter statuses status-precedence))
          statement (first (filter #(= status (:status %)) matches))]
      (cond-> {:status status}
        (:justification statement) (assoc :justification (:justification statement))
        (:status-notes statement) (assoc :notes (:status-notes statement))))))

(def ^:private exempting-statuses
  #{:not-affected :fixed})

(defn exempted?
  "Returns true if `vex-entry` (as returned by `vex-entry`, or nil) exempts its
   vulnerability from policy blocking -- a `:not-affected` or `:fixed` VEX
   status. `:affected`/`:under-investigation` (or no matching statement at all)
   never exempt."
  [vex-entry]
  (boolean (and vex-entry (contains? exempting-statuses (:status vex-entry)))))
