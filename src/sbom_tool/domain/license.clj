(ns sbom-tool.domain.license
  "Pure domain logic for evaluating and classifying component licenses."
  (:require [clojure.string :as string]
            [sbom-tool.domain.sbom :as sbom]))

;; TODO add spec for license policies

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

(defn license-status
  "Returns the status of `identifier` under `policy`: `:white` if
   whitelisted, `:black` if blacklisted, `:grey` otherwise."
  [policy identifier]
  (cond
    (nil? identifier) :grey
    (contains? (:whitelist policy) identifier) :white
    (contains? (:blacklist policy) identifier) :black
    :else :grey))

(defn component-report
  "Returns the license report for a single `component`, given `policies`."
  [policies component]
  (let [policy (policy-for policies (::sbom/component-type component))]
    {:id (::sbom/id component)
     :name (::sbom/name component)
     :version (::sbom/version component)
     :component-type (::sbom/component-type component)
     :licenses (into []
                      (map (fn [license]
                             (let [identifier (license-identifier license)]
                               {:license identifier
                                :status (license-status policy identifier)})))
                      (component-licenses component))}))

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
