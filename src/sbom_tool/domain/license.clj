(ns sbom-tool.domain.license
  "Pure domain logic for evaluating and classifying component licenses."
  (:require [clojure.spec.alpha :as s]
            [clojure.string :as string]
            [sbom-tool.domain.sbom :as sbom]))

(s/def ::whitelist (s/coll-of ::sbom/non-empty-string :kind set?))
(s/def ::blacklist (s/coll-of ::sbom/non-empty-string :kind set?))

(s/def ::type-policy
  (s/keys :opt-un [::whitelist ::blacklist]))

(s/def ::policy-key
  (s/or :default #{:default} :component-type ::sbom/component-type))

;; Identifies a specific component in a `::proprietary` or `::reviewed` set:
;; a bare component name, a {:name ... :version ...} map narrowing the
;; match to an exact version, or a {:purl ...} map matching by purl alone.
(s/def ::component-matcher
  (s/or :name ::sbom/non-empty-string
        :name-matcher (s/keys :req-un [::sbom/name] :opt-un [::sbom/version])
        :purl-matcher (s/keys :req-un [::sbom/purl])))

(s/def ::component-matchers (s/coll-of ::component-matcher :kind set?))

(s/def ::proprietary ::component-matchers)
(s/def ::reviewed ::component-matchers)

(s/def ::type-policies (s/map-of ::policy-key ::type-policy))

;; ::policies can no longer be a plain `map-of` once :proprietary/:reviewed
;; are reserved keys with a different value shape than a `::type-policy`;
;; split validation into the reserved keys plus everything else.
(s/def ::policies
  (s/and map?
         #(s/valid? ::proprietary (get % :proprietary #{}))
         #(s/valid? ::reviewed (get % :reviewed #{}))
         #(s/valid? ::type-policies (apply dissoc % [:proprietary :reviewed]))))

(defn license-identifier
  "Returns the identifying string of `license`, preferring its SPDX id
   over its plain name."
  [license]
  (or (::sbom/license-id license) (::sbom/license-name license)))

(defn license-url
  "Returns the URL associated with `license`, if any -- typically present
   when a license could only be resolved to a free-text name pointing
   elsewhere for the actual license terms."
  [license]
  (::sbom/license-url license))

(defn component-licenses
  "Returns the distinct licenses declared, concluded or detected from files
   for `component`."
  [component]
  (let [{:keys [::sbom/declared ::sbom/concluded ::sbom/from-files]} (::sbom/licenses component)]
    (into #{} (concat declared concluded from-files))))

(defn policy-for
  "Returns the usage-specific policy for `component-type`, falling back to
   the `:default` policy."
  [policies component-type]
  (get policies component-type (:default policies)))

(defn- normalize-component-matcher
  [matcher]
  (if (string? matcher) {:name matcher} matcher))

(defn- matches-any?
  [matchers component]
  (boolean
   (some (fn [matcher]
           (let [{:keys [name version purl]} (normalize-component-matcher matcher)]
             (if purl
               (= purl (get-in component [::sbom/identifiers ::sbom/purl]))
               (and (= name (::sbom/name component))
                    (or (nil? version) (= version (::sbom/version component)))))))
         matchers)))

(defn proprietary?
  "Returns true if `component` matches any entry of `proprietary` (the
   policy's :proprietary set): an exact purl match, or else a name match,
   optionally narrowed to an exact version."
  [proprietary component]
  (matches-any? proprietary component))

(defn reviewed?
  "Returns true if `component` matches any entry of `reviewed` (the
   policy's :reviewed set), under the same matching rule as `proprietary?`."
  [reviewed component]
  (matches-any? reviewed component))

(defn license-status
  "Returns the status of `identifier` under `policy`: `:white` if
   whitelisted, `:black` if blacklisted, `:grey` otherwise."
  [policy identifier]
  (cond
    (nil? identifier) :grey
    (contains? (:whitelist policy) identifier) :white
    (contains? (:blacklist policy) identifier) :black
    :else :grey))

(defn spdx-license-name
  "Returns the SPDX-canonical name for `identifier` (e.g. \"MIT License\"
   for \"MIT\") from `spdx-licenses` -- a map of license id to license
   list info, as returned by
   `sbom-tool.adapter.license.spdx/read-license-list` -- or nil if
   `identifier` isn't a single id directly present in it (e.g. a compound
   AND/OR expression, a custom `LicenseRef-` id, or `spdx-licenses` itself
   is nil because no license list was loaded)."
  [spdx-licenses identifier]
  (get-in spdx-licenses [identifier :name]))

(defn spdx-license-url
  "Returns the URL of `identifier`'s official SPDX license detail page
   (e.g. \"https://spdx.org/licenses/MIT.html\" for \"MIT\") from
   `spdx-licenses`, under the same resolution rules as
   `spdx-license-name` (nil for a compound expression, a custom
   `LicenseRef-` id, or when no license list was loaded)."
  [spdx-licenses identifier]
  (get-in spdx-licenses [identifier :license-url]))

(defn license-entry
  "Returns the explicit report entry for `identifier` under `policy`,
   given the loaded `spdx-licenses`: `:license-id` (`identifier` itself),
   `:license-name` (see `spdx-license-name`, nil when unresolved),
   `:license-url` (see `spdx-license-url`, nil under the same
   conditions -- not to be confused with a license's own `:url`, its
   declared URL from the SBOM document itself, added separately by
   `sbom-tool.application.report/unidentified-licenses`) and `:status`
   (see `license-status`). This is the entry shape shared by every
   component-level license report (`component-report`, and
   `sbom-tool.application.report`'s `multi-licensed` and
   `unidentified-licenses`)."
  [policy spdx-licenses identifier]
  {:license-id identifier
   :license-name (spdx-license-name spdx-licenses identifier)
   :license-url (spdx-license-url spdx-licenses identifier)
   :status (license-status policy identifier)})

(defn- reviewed-status
  "Downgrades `status` to `:reviewed` when it's one of the \"needs
   attention\" statuses (`:grey`, `:no-license`), leaving `:white`,
   `:black` and `:proprietary` untouched -- reviewing a component resolves
   ambiguity, it never overrides an already-decided or already-explained
   status."
  [status]
  (if (#{:grey :no-license} status) :reviewed status))

(defn component-report
  "Returns the license report for a single `component`, given `policies`.
   Each license entry is a `license-entry`, given the component's own
   usage-specific policy (see `policy-for`) -- except when `component` has
   no licenses at all, in which case a single synthetic entry is returned
   instead of an empty vector, its `:status` `:proprietary` if `component`
   matches the policy's `:proprietary` set, `:no-license` otherwise. Either
   way, `:grey`/`:no-license` statuses are further downgraded to
   `:reviewed` when `component` matches the policy's `:reviewed` set (see
   `reviewed-status`)."
  [policies spdx-licenses component]
  (let [policy (policy-for policies (::sbom/component-type component))
        licenses (component-licenses component)
        raw-licenses (if (empty? licenses)
                       [{:license-id nil :license-name nil :license-url nil
                         :status (if (proprietary? (:proprietary policies) component)
                                   :proprietary
                                   :no-license)}]
                       (into []
                             (map (comp (partial license-entry policy spdx-licenses) license-identifier))
                             licenses))]
    {:id (::sbom/id component)
     :name (::sbom/name component)
     :version (::sbom/version component)
     :component-type (::sbom/component-type component)
     :licenses (if (reviewed? (:reviewed policies) component)
                 (mapv #(update % :status reviewed-status) raw-licenses)
                 raw-licenses)}))

(def ^:private license-expression-token-re
  ;; Tokenizes into "(", ")", the AND/OR operator keywords, or the runs of
  ;; text between them (license ids, or arbitrary free text for
  ;; non-compound identifiers).
  #"\(|\)|\bAND\b|\bOR\b|[^()]+?(?=\(|\)|\bAND\b|\bOR\b|$)")

(defn- tokenize-license-expression
  [expression]
  (->> (re-seq license-expression-token-re expression)
       (map string/trim)
       (remove string/blank?)))

(declare ^:private parse-or)

(defn- parse-atom
  [tokens]
  (if (= "(" (first tokens))
    (let [[node remaining] (parse-or (rest tokens))]
      (if (= ")" (first remaining))
        [node (rest remaining)]
        [node remaining]))
    [{:op :id :id (first tokens)} (rest tokens)]))

(defn- parse-and
  [tokens]
  (let [[first-node rest-tokens] (parse-atom tokens)]
    (loop [args [first-node] tokens rest-tokens]
      (if (= "AND" (first tokens))
        (let [[node remaining] (parse-atom (rest tokens))]
          (recur (conj args node) remaining))
        [(if (= 1 (count args)) (first args) {:op :and :args args}) tokens]))))

(defn- parse-or
  [tokens]
  (let [[first-node rest-tokens] (parse-and tokens)]
    (loop [args [first-node] tokens rest-tokens]
      (if (= "OR" (first tokens))
        (let [[node remaining] (parse-and (rest tokens))]
          (recur (conj args node) remaining))
        [(if (= 1 (count args)) (first args) {:op :or :args args}) tokens]))))

(defn- expression-choices
  "Evaluates a parsed license expression `node` into its distinct choices,
   each a set of the license ids that must be satisfied together. AND
   distributes over nested OR choices, e.g. \"(MIT OR X) AND Y\" yields
   the choices #{MIT Y} and #{X Y}."
  [node]
  (case (:op node)
    :id (list #{(:id node)})
    :or (mapcat expression-choices (:args node))
    :and (reduce (fn [combined-choices arg]
                   (for [combined combined-choices
                         choice (expression-choices arg)]
                     (into combined choice)))
                 (list #{})
                 (:args node))))

(defn license-choices
  "Parses an SPDX license expression `identifier` into the distinct choices
   it offers, honoring both the disjunctive OR and the conjunctive AND
   operator as well as nested parentheses. Each choice is a set of the
   license ids that must be satisfied together, e.g.
   \"MIT OR Apache-2.0\" -> (#{\"MIT\"} #{\"Apache-2.0\"}), and
   \"MIT AND Apache-2.0\" -> (#{\"MIT\" \"Apache-2.0\"}). Returns a single
   choice containing `identifier` unchanged for identifiers that are not a
   compound expression, or that fail to parse as one."
  [identifier]
  (when identifier
    (let [tokens (tokenize-license-expression identifier)]
      (if (some #{"AND" "OR"} tokens)
        (let [[node remaining] (parse-or tokens)]
          (if (seq remaining)
            (list #{identifier})
            (expression-choices node)))
        (list #{identifier})))))

(defn component-license-choices
  "Returns the distinct set of license choices for `component`, expanding
   any compound (AND/OR) license expressions into their individual
   choices."
  [component]
  (->> (component-licenses component)
       (keep license-identifier)
       (mapcat license-choices)
       (into #{})))

(defn- resolvable-id?
  [id]
  (not (string/starts-with? id "LicenseRef-")))

(defn spdx-identifiable?
  "Returns true if `license` carries a license identifier that can be
   resolved to a standard SPDX license. Expands compound AND/OR license
   expressions into the individual ids they reference (using the same
   parser as `license-choices`) and requires every one of them to be
   resolvable, i.e. not a custom `LicenseRef-` identifier -- so e.g.
   \"MIT OR Apache-2.0\" is identifiable but \"MIT OR LicenseRef-custom\"
   is not. Licenses that carry no `::license-id` at all, only a free-text
   `::license-name`, are never considered identifiable."
  [license]
  (when-let [id (::sbom/license-id license)]
    (every? resolvable-id? (into #{} cat (license-choices id)))))
