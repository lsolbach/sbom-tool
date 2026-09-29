(ns sbom-tool.domain.cvss
  "Pure domain logic for parsing a CVSS Base vector string (v3.0/v3.1, e.g.
   `\"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H\"`, or v2, e.g.
   `\"AV:N/AC:L/Au:N/C:N/I:N/A:C\"`) and computing its Base Score and
   canonical `::sbom/severity` keyword, per the CVSS v3.1 Specification
   (https://www.first.org/cvss/v3-1/specification-document) and NVD's CVSS
   v2 Complete Documentation (https://nvd.nist.gov/vuln-metrics/cvss/v2-calculator)
   respectively -- v3.0 uses the same Base metrics and the same Base Score
   formula as v3.1, so both share the v3 implementation; v2 predates
   Scope/Attack-Requirements entirely and has its own, structurally
   simpler formula and its own three-band (no \"Critical\") qualitative
   scale, so it gets its own sibling set of functions (`parse-vector-v2`/
   `base-score-v2`/`severity-of-score-v2`/`vector->severity-v2`) rather
   than sharing the v3 ones. Every vulnerability-database adapter that
   only has a CVSS vector string (rather than a ready-made numeric score,
   e.g. deps.dev's `cvss3Score`, or a ready-made qualitative severity,
   e.g. GitHub Advisory Database's `severity`) shares this single
   implementation instead of re-deriving one.

   Only Base metrics are parsed and scored -- Temporal and Environmental
   metrics, when present in a vector, are ignored rather than rejected
   (see `parse-vector`/`parse-vector-v2`)."
  (:require [clojure.string :as string]))

(def ^:private av-weights
  {"N" 0.85 "A" 0.62 "L" 0.55 "P" 0.2})

(def ^:private ac-weights
  {"L" 0.77 "H" 0.44})

(def ^:private pr-weights-scope-unchanged
  {"N" 0.85 "L" 0.62 "H" 0.27})

(def ^:private pr-weights-scope-changed
  {"N" 0.85 "L" 0.68 "H" 0.5})

(def ^:private ui-weights
  {"N" 0.85 "R" 0.62})

(def ^:private cia-weights
  {"H" 0.56 "L" 0.22 "N" 0.0})

(defn- pr-weights
  [scope]
  (if (= "C" scope) pr-weights-scope-changed pr-weights-scope-unchanged))

(defn- valid-metrics?
  [{:strs [AV AC PR UI S C I A]}]
  (and (contains? av-weights AV)
       (contains? ac-weights AC)
       (contains? ui-weights UI)
       (contains? #{"U" "C"} S)
       (contains? (pr-weights S) PR)
       (contains? cia-weights C)
       (contains? cia-weights I)
       (contains? cia-weights A)))

(defn parse-vector
  "Parses a CVSS v3.0/v3.1 Base vector string into `{:version :av :ac :pr
   :ui :s :c :i :a}` (the raw single-letter metric values, not yet
   resolved to their numeric weights -- see `base-score`), or nil if
   `vector-string` doesn't start with a recognized `CVSS:3.0`/`CVSS:3.1`
   prefix, or is missing/carries an unrecognized value for any of the
   eight required Base metrics. Any Temporal/Environmental metrics present
   after the Base ones are parsed but ignored -- they neither invalidate
   an otherwise well-formed Base vector nor affect `base-score`."
  [vector-string]
  (when (and vector-string
             (or (string/starts-with? vector-string "CVSS:3.0/")
                 (string/starts-with? vector-string "CVSS:3.1/")))
    (let [version (subs vector-string 5 8)
          metrics (into {}
                        (keep (fn [segment]
                                (let [parts (string/split segment #":")]
                                  (when (= 2 (count parts))
                                    parts))))
                        (string/split (subs vector-string 9) #"/"))]
      (when (valid-metrics? metrics)
        {:version version
         :av (get metrics "AV")
         :ac (get metrics "AC")
         :pr (get metrics "PR")
         :ui (get metrics "UI")
         :s (get metrics "S")
         :c (get metrics "C")
         :i (get metrics "I")
         :a (get metrics "A")}))))

(defn- roundup
  "The CVSS spec's exact rounding rule (Appendix A): scale by 100000, round
   to the nearest integer, then round *up* to the nearest multiple of
   10000 before scaling back down to one decimal place -- never a plain
   `Math/round` to one decimal, which can round e.g. 4.02 down to 4.0
   instead of up to 4.1."
  [x]
  (let [scaled (Math/round (* x 100000.0))]
    (if (zero? (mod scaled 10000))
      (/ scaled 100000.0)
      (/ (* 10000 (inc (quot scaled 10000))) 100000.0))))

(defn base-score
  "Computes the CVSS v3 Base Score in `[0.0, 10.0]` for a parsed vector
   `metrics` map (see `parse-vector`), per the CVSS v3.1 Specification's
   Base Score formula (section 7.4, identical between v3.0 and v3.1)."
  [{:keys [av ac pr ui s c i a]}]
  (let [c-w (get cia-weights c)
        i-w (get cia-weights i)
        a-w (get cia-weights a)
        iscbase (- 1 (* (- 1 c-w) (- 1 i-w) (- 1 a-w)))
        scope-changed? (= "C" s)
        impact (if scope-changed?
                 (- (* 7.52 (- iscbase 0.029))
                    (* 3.25 (Math/pow (- iscbase 0.02) 15)))
                 (* 6.42 iscbase))
        exploitability (* 8.22 (get av-weights av) (get ac-weights ac) (get (pr-weights s) pr) (get ui-weights ui))]
    (if (<= impact 0)
      0.0
      (roundup (min 10.0 (* (if scope-changed? 1.08 1.0) (+ impact exploitability)))))))

(defn severity-of-score
  "Maps a numeric CVSS Base Score `score` (or nil, when no score is
   available at all) to a canonical `::sbom/severity`, using the same
   qualitative ranges NVD itself uses."
  [score]
  (cond
    (nil? score) :unknown
    (>= score 9.0) :critical
    (>= score 7.0) :high
    (>= score 4.0) :medium
    (>= score 0.1) :low
    :else :unknown))

(defn vector->severity
  "Parses `vector-string` and computes its canonical `::sbom/severity` in
   one step (`parse-vector` then `base-score` then `severity-of-score`),
   or nil if `vector-string` doesn't parse -- nil-safe throughout, so a
   caller can tell \"no usable vector\" (nil) apart from \"a real, if low,
   severity\" (a keyword)."
  [vector-string]
  (some-> vector-string parse-vector base-score severity-of-score))

(def ^:private av-weights-v2
  {"L" 0.395 "A" 0.646 "N" 1.0})

(def ^:private ac-weights-v2
  {"H" 0.35 "M" 0.61 "L" 0.71})

(def ^:private au-weights-v2
  {"M" 0.45 "S" 0.56 "N" 0.704})

(def ^:private cia-weights-v2
  {"N" 0.0 "P" 0.275 "C" 0.660})

(defn- valid-metrics-v2?
  [{:strs [AV AC Au C I A]}]
  (and (contains? av-weights-v2 AV)
       (contains? ac-weights-v2 AC)
       (contains? au-weights-v2 Au)
       (contains? cia-weights-v2 C)
       (contains? cia-weights-v2 I)
       (contains? cia-weights-v2 A)))

(defn parse-vector-v2
  "Parses a CVSS v2 Base vector string (no version prefix, e.g.
   `\"AV:N/AC:L/Au:N/C:N/I:N/A:C\"`) into `{:av :ac :au :c :i :a}`, or nil
   if any of the six required Base metrics is missing or carries an
   unrecognized value. Any Temporal/Environmental metrics present after
   the Base ones are parsed but ignored, the same permissive passthrough
   `parse-vector` gives v3's Temporal/Environmental segments."
  [vector-string]
  (when vector-string
    (let [metrics (into {}
                         (keep (fn [segment]
                                 (let [parts (string/split segment #":")]
                                   (when (= 2 (count parts))
                                     parts))))
                         (string/split vector-string #"/"))]
      (when (valid-metrics-v2? metrics)
        {:av (get metrics "AV")
         :ac (get metrics "AC")
         :au (get metrics "Au")
         :c (get metrics "C")
         :i (get metrics "I")
         :a (get metrics "A")}))))

(defn- round-to-tenth
  [x]
  (/ (Math/round (* x 10.0)) 10.0))

(defn base-score-v2
  "Computes the CVSS v2 Base Score in `[0.0, 10.0]` for a parsed vector
   `metrics` map (see `parse-vector-v2`), per NVD's CVSS v2 Complete
   Documentation's Base Score formula -- structurally simpler than v3's
   `base-score` (one formula, no Scope branch)."
  [{:keys [av ac au c i a]}]
  (let [impact (* 10.41 (- 1 (* (- 1 (get cia-weights-v2 c))
                                 (- 1 (get cia-weights-v2 i))
                                 (- 1 (get cia-weights-v2 a)))))
        exploitability (* 20 (get av-weights-v2 av) (get ac-weights-v2 ac) (get au-weights-v2 au))
        f-impact (if (zero? impact) 0 1.176)]
    (round-to-tenth (* f-impact (- (+ (* 0.6 impact) (* 0.4 exploitability)) 1.5)))))

(defn severity-of-score-v2
  "Maps a numeric CVSS v2 Base Score `score` (or nil, when no score is
   available at all) to a canonical `::sbom/severity`, using CVSS v2's own
   three-band qualitative scale (Low/Medium/High -- v2 predates
   \"Critical\"). Never returns `:critical`, unlike `severity-of-score`
   (v3/v4's four-band scale) -- applying that scale's thresholds to a v2
   score would misclassify a high-but-not-critical-by-v2's-own-standard
   score as `:critical`."
  [score]
  (cond
    (nil? score) :unknown
    (>= score 7.0) :high
    (>= score 4.0) :medium
    (>= score 0.1) :low
    :else :unknown))

(defn vector->severity-v2
  "Parses `vector-string` as a CVSS v2 Base vector and computes its
   canonical `::sbom/severity` in one step (`parse-vector-v2` then
   `base-score-v2` then `severity-of-score-v2`), or nil if `vector-string`
   doesn't parse -- nil-safe throughout, mirroring `vector->severity`."
  [vector-string]
  (some-> vector-string parse-vector-v2 base-score-v2 severity-of-score-v2))
