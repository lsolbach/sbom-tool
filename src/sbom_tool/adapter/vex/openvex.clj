(ns sbom-tool.adapter.vex.openvex
  "Adapter for OpenVEX (https://github.com/openvex/spec), a JSON-based VEX
   (Vulnerability Exploitability eXchange) format: reads every `*.vex.json`
   document under a directory (e.g. one per supplier), mapping each
   `statements` entry to the canonical `sbom-tool.domain.vex` model. Populates
   `:vex-statements` in `sbom-tool.application.repository/state` when
   `--vex-path` is given -- no VEX is applied otherwise (see
   `read-vex-statements`).

   Unlike the vulnerability-database adapters (`deps-dev`, `github-advisory`),
   this is a purely local, offline read -- a VEX file the user pointed
   `--vex-path` at is exactly as much \"their input\" as an SBOM file, so a
   malformed file fails loudly (an ex-info, same as
   `sbom-tool.adapter.sbom.cdx`) rather than warning and continuing."
  (:require [cheshire.core :as json]
            [babashka.fs :as fs]
            [clojure.string :as string]
            [sbom-tool.domain.vex :as vex]))

(def ^:private json-processing-exception-class
  "Resolved via `Class/forName` rather than referenced as a `catch` class
   literal, so this namespace also loads under babashka: its SCI interpreter
   cannot resolve `com.fasterxml.jackson.core.JsonProcessingException` as a
   catch clause at analysis time, even though the class itself is present at
   runtime (babashka's `cheshire` is backed by real Jackson). See
   `sbom-tool.adapter.sbom.cdx` for the same fix."
  (Class/forName "com.fasterxml.jackson.core.JsonProcessingException"))

(defn vex-files
  "Returns the list of OpenVEX files under `path`."
  [path]
  (->> (fs/glob path "**{.vex.json}")
       (map str)))

(defn read-vex-document
  "Returns the data of the OpenVEX JSON file at `filename`."
  [filename]
  (try
    (-> filename (slurp) (json/parse-string keyword))
    (catch java.io.FileNotFoundException e
      (let [msg (str "file not found: " filename)]
        (throw (ex-info msg
                         {:sbom-tool/error-type :vex-file-not-found :path filename}
                         e))))
    (catch Exception e
      (if (instance? json-processing-exception-class e)
        (let [msg (str "malformed JSON: " (ex-message e))]
          (throw (ex-info msg
                           {:sbom-tool/error-type :malformed-vex-json :path filename}
                           e)))
        (throw e)))))

(defn- remove-nils
  [m]
  (into {} (remove (comp nil? val)) m))

(defn- id-like
  "Returns `s` if it looks like a `pkg:`/`cpe:` identifier of `prefix`, else
   nil."
  [s prefix]
  (when (and (string? s) (string/starts-with? s prefix))
    s))

(def ^:private at-id-key
  "The `@id` key, built via `keyword` rather than the `:@id` literal: babashka's
   SCI reader fails to parse a keyword literal starting with `@` (verified in
   this session), even though the class itself is a perfectly valid Clojure
   keyword at runtime -- the same class of babashka/SCI portability gap
   documented for `JsonProcessingException` catch-clauses elsewhere in this
   project's adapters."
  (keyword "@id"))

(defn product-identifiers
  "Extracts `{:purl :cpe}` from one OpenVEX `products[]` entry: a bare string
   (some real-world documents use one directly instead of `{\"@id\" ...}`), or
   a map preferring its `:identifiers` (`:purl`/`:cpe23`) and falling back to
   inferring from a bare `:@id` by its `pkg:`/`cpe:` prefix. An identifier
   scheme this tool doesn't recognize (e.g. a SWID tag) contributes neither --
   not an error, the same \"unsupported, not broken\" treatment
   `sbom-tool.adapter.vulnerability.github-advisory/supported-entry` already
   gives an unrecognized purl type."
  [product]
  (if (string? product)
    (remove-nils {:purl (id-like product "pkg:") :cpe (id-like product "cpe:")})
    (let [id (get product at-id-key)
          identifiers (:identifiers product)]
      (remove-nils {:purl (or (:purl identifiers) (id-like id "pkg:"))
                    :cpe (or (:cpe23 identifiers) (id-like id "cpe:"))}))))

(def ^:private statuses
  "Maps OpenVEX's snake_case `status` values to the domain's kebab-case
   keywords."
  {"affected" :affected
   "not_affected" :not-affected
   "fixed" :fixed
   "under_investigation" :under-investigation})

(def ^:private justifications
  "Maps OpenVEX's snake_case `justification` values (only meaningful for a
   `not_affected` status) to the domain's kebab-case keywords."
  {"component_not_present" :component-not-present
   "vulnerable_code_not_present" :vulnerable-code-not-present
   "vulnerable_code_not_in_execute_path" :vulnerable-code-not-in-execute-path
   "vulnerable_code_cannot_be_controlled_by_adversary" :vulnerable-code-cannot-be-controlled-by-adversary
   "inline_mitigations_already_exist" :inline-mitigations-already-exist})

(defn map-statement
  "Maps an OpenVEX statement to the canonical `sbom-tool.domain.vex` statement
   model, or nil when its `vulnerability.name` or `status` don't resolve to
   something usable (mirrors the existing vulnerability adapters'
   nil-on-unusable-id style)."
  [{:keys [vulnerability products status justification] status-notes :status_notes}]
  (when-let [id (:name vulnerability)]
    (when-let [status (get statuses status)]
      (let [identifiers (map product-identifiers products)]
        (remove-nils
         {:vulnerability-id id
          :aliases (not-empty (into [] (:aliases vulnerability)))
          :status status
          :justification (get justifications justification)
          :status-notes status-notes
          :purls (not-empty (into #{} (keep :purl) identifiers))
          :cpes (not-empty (into #{} (keep :cpe) identifiers))})))))

(defn- warn
  [msg]
  (binding [*out* *err*]
    (println (str "Warning: " msg))))

(defn read-vex-statements
  "Reads every `*.vex.json` file under `path`, mapping every document's
   `statements` to the canonical `sbom-tool.domain.vex` model (dropping any
   that don't map, see `map-statement`). Returns nil when `path` is nil -- no
   VEX configured is the default, silent, not a warning -- otherwise warns on
   `*err*` if `path` has zero matching files (opted in but found nothing)."
  [path]
  (when path
    (let [files (vex-files path)]
      (when (empty? files)
        (warn (str "no *.vex.json files found under " path)))
      (into []
            (comp (map read-vex-document)
                  (mapcat :statements)
                  (keep map-statement))
            files))))
