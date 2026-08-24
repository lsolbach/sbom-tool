# Plan: Human-Readable Error Reporting for the CLI

**Status:** proposed
**Date:** 2026-08-24
**Related:** [dev/assessments/project-assessment.md](../assessments/project-assessment.md) ("Error Handling: Weak")

## Problem

Today, any failure below the CLI argument-parsing step surfaces to the user as a raw JVM stack trace instead of an actionable message, and the process still exits with the generic default uncaught-exception exit code. Concretely:

- [src/sbom_tool/adapter/ui/cli.clj](../../src/sbom_tool/adapter/ui/cli.clj#L110-L127) only wraps `cli/parse-opts` in a `try/catch`; `handle`, `initialize-state`, and `dispatch` ([cli.clj:154-166](../../src/sbom_tool/adapter/ui/cli.clj#L154-L166)) run completely unguarded.
- That one `catch` block itself has a bug: on exception it prints a message and returns `nil` instead of an `:exit-message`, so `-main` ([cli.clj:170-185](../../src/sbom_tool/adapter/ui/cli.clj#L170-L185)) falls through to `(handle nil)` and fails again, later, less clearly.
- `-main` also reads `(:debug options)` ([cli.clj:178](../../src/sbom_tool/adapter/ui/cli.clj#L178)) but no `--debug`/`-d` option is declared in `cli-opts` ([cli.clj:69-84](../../src/sbom_tool/adapter/ui/cli.clj#L69-L84)) — it's always `nil`, so this hook does nothing today.
- Policy loading ([src/sbom_tool/adapter/policies.clj](../../src/sbom_tool/adapter/policies.clj)) can throw: `slurp` (`FileNotFoundException` for a bad `-l`/`-V` path), `edn/read-string` (malformed EDN), and the `validate!` spec check added previously (`ex-info` with `:path`/`:explain-data`, already reasonably structured but not yet rendered nicely).
- SBOM loading ([src/sbom_tool/adapter/sbom/cdx.clj](../../src/sbom_tool/adapter/sbom/cdx.clj#L7-18), [src/sbom_tool/adapter/sbom/spdx.clj](../../src/sbom_tool/adapter/sbom/spdx.clj#L8-19)) can throw from `slurp` (missing/unreadable file) or `cheshire.core/parse-string` (malformed JSON), with zero context about *which* file failed once the exception reaches the top.
- A silently-empty result is also a footgun: `fs/glob` returns `[]` if `-I` points at a non-existent or empty directory, so a typo'd input path produces a clean "zero components" report instead of any warning.
- [src/sbom_tool/domain/vulnerability.clj](../../src/sbom_tool/domain/vulnerability.clj#L65-67) parses `:expiry-date` with `LocalDate/parse` with no guard; the `iso-date?` spec predicate added earlier ([vulnerability.clj:8-10](../../src/sbom_tool/domain/vulnerability.clj#L8-L10)) protects policies loaded through `read-vulnerability-policy-file`, but not exemptions reaching this function any other way (defense in depth).
- There are no CLI-level tests today (`test/sbom_tool/adapter/ui/` does not exist), and `System/exit` is called directly from deep in the call stack ([cli.clj:103](../../src/sbom_tool/adapter/ui/cli.clj#L103), [cli.clj:160](../../src/sbom_tool/adapter/ui/cli.clj#L160)), which would kill the test JVM if exercised directly.

## Goals

1. Replace raw stack traces with short, human-readable messages that say *what* went wrong, *which file/value* caused it, and (where relevant) *how to fix it* — in the same voice as the existing `usage-msg`/`error-msg` helpers.
2. Keep a single, well-documented exit-code scheme, without breaking the already-documented `--fail-on-violations` behavior (README: "the process exits with status 1 if any are found").
3. Make the error path testable without invoking `System/exit` inside `clojure.test`.
4. Add an actual `--debug`/`-d` flag so the existing `(:debug options)` read in `-main` does something: print the full exception chain for troubleshooting, on top of (not instead of) the friendly message.
5. Do this with minimal architectural disruption: keep pure domain/application code exception-free where reasonably possible; concentrate wrapping/formatting in the adapter layer, closest to the I/O that can fail.

## Non-goals

- Changing what counts as a policy violation, or the default report/output selection.
- Introducing a logging framework; `println`/`*err*` remain sufficient for a CLI tool this size.
- Retrying or auto-recovering from errors (e.g. re-globbing, re-parsing) — the goal is reporting, not resilience.
- Validating SBOM documents against `sbom-tool.domain.sbom` specs at parse time (a real gap noted in the assessment, but a separate, larger effort from wiring up error *reporting*; see "Follow-ups" below).

## Design overview

### Exit codes

| Code | Meaning | Status today |
|------|---------|---------------|
| 0 | Success | unchanged |
| 1 | CLI usage error (bad/missing arguments, `--help`) **or** `--fail-on-violations` triggered | unchanged (already documented in README) |
| 2 | Runtime/data error while reading SBOMs or policies, or while rendering a report (new) | currently falls through to the JVM's default uncaught-exception exit code (also happens to be 1, but with a stack trace and no message) |

Code `2` is new and exclusively for the failure modes this plan targets, so scripts that already branch on "0 = clean, 1 = violations found" keep working, and can additionally distinguish "2 = tool couldn't run at all" if they choose to.

### Error taxonomy

Introduce one qualified keyword per distinct, anticipated failure, attached to `ex-info` under a `:sbom-tool/error-type` key so a single dispatch function can render all of them consistently:

| `:sbom-tool/error-type` | Raised by | Typical cause |
|---|---|---|
| `:policy-file-not-found` | `policies.clj` | bad `-l`/`-V` path |
| `:malformed-policy-edn` | `policies.clj` | syntax error in policy EDN |
| `:invalid-policy` | `policies.clj` (existing `validate!`) | policy fails its spec |
| `:sbom-file-not-found` | `cdx.clj`/`spdx.clj` | file vanished/unreadable between glob and read |
| `:malformed-sbom-json` | `cdx.clj`/`spdx.clj` | invalid JSON |
| `:report-rendering-failed` | `json.clj`/`markdown.clj` (via a thin wrapper in `template.clj` or `cli.clj`) | malformed/unexpected report data reaching a renderer |

Every one of these carries at least `:path` (the offending file, when there is one) and `:cause` (the original `Throwable`, via `ex-info`'s third argument so `ex-cause` keeps working); this keeps `--debug` able to show the real underlying exception without re-parsing message strings.

Unanticipated failures (anything not raised through this taxonomy — e.g. a `NullPointerException` from a code path nobody wrapped) still get caught by a final generic handler, so the tool never crashes with a bare trace by default even for cases this plan didn't enumerate; it just reports them less specifically ("An unexpected error occurred: ...").

### Where wrapping happens

Wrap exactly at the point where a checked/unchecked library exception would otherwise leak (`slurp`, `edn/read-string`, `json/parse-string`, `LocalDate/parse`), inside the adapter functions that already own that I/O. This keeps `sbom-tool.domain.*` free of CLI/error-reporting concerns, consistent with the project's Clean Architecture layering (see [AGENTS.md](../../AGENTS.md) and [.github/instructions/clojure.instructions.md](../../.github/instructions/clojure.instructions.md)).

### Where catching/formatting happens

One boundary, at the edge of the CLI adapter: a new `run` function in `cli.clj` (or a small new `sbom-tool.adapter.ui.errors` namespace) wraps `initialize-state` + `dispatch` in a `try/catch`, turns any exception into `{:exit-code ... :message ...}}`, and `-main` is the *only* place that still prints that message and calls `System/exit`. This keeps `run` pure-enough to unit test directly.

## Step-by-step implementation

### Step 1 — Add an error-formatting namespace

Create `src/sbom_tool/adapter/ui/errors.clj`:

```clojure
(ns sbom-tool.adapter.ui.errors
  "Formats exceptions raised while reading SBOMs/policies or rendering
   reports into short, human-readable CLI messages.")

(def runtime-error-exit-code 2)

(defmulti friendly-message
  "Returns a human-readable message for `ex`, dispatching on its
   `:sbom-tool/error-type` (via `ex-data`), or `::unknown` if `ex` carries
   no such tag."
  (fn [ex] (:sbom-tool/error-type (ex-data ex) ::unknown)))

(defmethod friendly-message :policy-file-not-found
  [ex]
  (str "Could not read the policy file " (:path (ex-data ex)) ": " (ex-message ex)))

(defmethod friendly-message :malformed-policy-edn
  [ex]
  (str "The policy file " (:path (ex-data ex)) " is not valid EDN: " (ex-message ex)))

(defmethod friendly-message :invalid-policy
  ;; the message already comes from `sbom-tool.adapter.policies/validate!`
  ;; via `s/explain-str`, which is already human-readable
  [ex]
  (ex-message ex))

(defmethod friendly-message :sbom-file-not-found
  [ex]
  (str "Could not read the SBOM file " (:path (ex-data ex)) ": " (ex-message ex)))

(defmethod friendly-message :malformed-sbom-json
  [ex]
  (str "The SBOM file " (:path (ex-data ex)) " is not valid JSON: " (ex-message ex)))

(defmethod friendly-message :report-rendering-failed
  [ex]
  (str "Could not render the report: " (ex-message ex)))

(defmethod friendly-message ::unknown
  [ex]
  (str "An unexpected error occurred: " (ex-message ex)))

(defn debug-details
  "Returns the full cause chain of `ex` as a string, for `--debug`."
  [ex]
  (->> (iterate ex-cause ex)
       (take-while some?)
       (map #(str (.getName (class %)) ": " (ex-message %)))
       (clojure.string/join "\nCaused by: ")))
```

Justification: a `defmulti` keyed on a namespaced keyword is idiomatic for this codebase (it already uses multimethods pervasively for format/output dispatch in `repository.clj` and `template.clj`), is trivially extensible when a new failure mode is identified later, and keeps every message's wording in one place for easy review/testing.

### Step 2 — Tag and wrap exceptions in `policies.clj`

Update [src/sbom_tool/adapter/policies.clj](../../src/sbom_tool/adapter/policies.clj):

- Give the existing `validate!` `ex-info` a `:sbom-tool/error-type :invalid-policy` key (it already carries `:path` and `:explain-data`; just add the one key so `errors/friendly-message` can dispatch on it).
- Wrap the `slurp`/`edn/read-string` pipeline so a missing file or a bad EDN syntax error becomes a tagged `ex-info` with the original exception preserved as the cause, instead of leaking `FileNotFoundException`/`RuntimeException` directly:

```clojure
(defn- read-edn-file
  "Reads and parses the EDN file at `path` (or `resource`, when `path` is
   nil), tagging read/parse failures as `error-type` for
   `sbom-tool.adapter.ui.errors/friendly-message`."
  [path resource error-type]
  (let [source (if path path (str "bundled default (" resource ")"))]
    (try
      (edn/read-string (if path (slurp path) (slurp (io/resource resource))))
      (catch java.io.FileNotFoundException e
        (throw (ex-info (str "file not found: " path)
                         {:sbom-tool/error-type :policy-file-not-found :path source} e)))
      (catch RuntimeException e
        (throw (ex-info (str "malformed EDN: " (ex-message e))
                         {:sbom-tool/error-type :malformed-policy-edn :path source} e))))))
```

  `read-license-policy-file`/`read-vulnerability-policy-file` then call `read-edn-file` and pass the result to `validate!` as before. (Keep `default-license-policy-resource`/`default-vulnerability-policy-resource` as-is; only the read/parse plumbing changes.)

- Add unit tests in a new `test/sbom_tool/adapter/policies_test.clj`:
  - reading a non-existent path raises an `ex-info` with `:sbom-tool/error-type :policy-file-not-found`.
  - reading a fixture with deliberately broken EDN syntax raises `:malformed-policy-edn`.
  - reading a fixture that parses but fails its spec (e.g. `:max-severity :not-a-severity`) still raises `:invalid-policy` (regression check that Step 2's tagging didn't disturb the existing `validate!` behavior added previously).
  - add the two new malformed fixtures under `test/resources/policies/` (e.g. `broken.edn`, `invalid-vulnerability-policy.edn`).

### Step 3 — Tag and wrap exceptions in the SBOM adapters

Apply the same pattern to [src/sbom_tool/adapter/sbom/cdx.clj](../../src/sbom_tool/adapter/sbom/cdx.clj#L13-18) and [src/sbom_tool/adapter/sbom/spdx.clj](../../src/sbom_tool/adapter/sbom/spdx.clj#L14-19), both of which share the exact same `read-json` shape:

```clojure
(defn read-json
  "Returns the data of the JSON file with the given `filename`."
  [filename]
  (try
    (-> filename (slurp) (json/parse-string keyword))
    (catch java.io.FileNotFoundException e
      (throw (ex-info (str "file not found: " filename)
                       {:sbom-tool/error-type :sbom-file-not-found :path filename} e)))
    (catch com.fasterxml.jackson.core.JsonProcessingException e
      (throw (ex-info (str "malformed JSON: " (ex-message e))
                       {:sbom-tool/error-type :malformed-sbom-json :path filename} e)))))
```

(`cheshire`'s parser exceptions are subclasses of `com.fasterxml.jackson.core.JsonProcessingException`; catching that instead of a bare `Exception` avoids masking unrelated bugs.)

Add a test per adapter (`test/sbom_tool/adapter/sbom/cdx_test.clj`, `.../spdx_test.clj` — neither exists yet) with a small malformed-JSON fixture, asserting the tagged `ex-info` is thrown with the right `:sbom-tool/error-type` and `:path`.

### Step 4 — Warn (not fail) on an empty input path

In `repository.clj`'s `:cdx`/`:spdx` `read-sboms` methods (or in `cdx-files`/`spdx-files` themselves), if the glob returns no files, `println` a one-line warning to `*err*` (e.g. `"Warning: no *.cdx.json files found under sboms"`) rather than silently proceeding — this directly targets the "typo'd `-I` path silently reports zero components" footgun called out in the assessment, without turning an arguably-valid "no files of this format" case into a hard error (a folder legitimately containing only `*.spdx.json` files should not warn about missing `*.cdx.json` when `-s :auto` is used). Exit code stays `0`.

This is a small, low-risk addition; keep it last/optional if time is constrained, since it is a UX nicety rather than the core ask (turning exceptions into readable messages).

### Step 5 — Defensive wrap in `vulnerability.clj`

In [src/sbom_tool/domain/vulnerability.clj](../../src/sbom_tool/domain/vulnerability.clj#L61-67), guard the still-unprotected `LocalDate/parse` call in `exemption-expired?` the same way `iso-date?` already does, so a policy that reaches this function through any path other than `read-vulnerability-policy-file` (e.g. constructed programmatically, or if `validate!` is ever bypassed) fails predictably instead of throwing a bare `DateTimeParseException` deep inside report generation:

```clojure
(defn- exemption-expired?
  [exemption today]
  (when-let [expiry-date (:expiry-date exemption)]
    (try
      (.isAfter today (LocalDate/parse expiry-date))
      (catch java.time.format.DateTimeParseException e
        (throw (ex-info (str "invalid exemption expiry-date: " expiry-date)
                         {:sbom-tool/error-type :invalid-policy :path nil} e))))))
```

This is a narrow, defense-in-depth change (the primary guard is still spec validation at policy-load time from the previous change); add one test asserting the new exception shape without needing to go through file I/O (call `vulnerability-status` directly with a hand-built policy carrying a bad date).

### Step 6 — Fix `validate-args` and add `--debug`

In [src/sbom_tool/adapter/ui/cli.clj](../../src/sbom_tool/adapter/ui/cli.clj#L110-L127):

- Add the missing option so the existing `(:debug options)` read in `-main` finally does something:

```clojure
["-d" "--debug" "Print full exception details on failure, for troubleshooting"]
```

- Fix the `catch` block so it actually returns an `:exit-message` instead of `nil` (today it prints and silently falls through to `handle`):

```clojure
(catch Exception e
  {:exit-message (str "Error validating the CLI arguments " args ".\n" (ex-message e))})
```

  (Drop the manual `.printStacktrace`; `--debug` now owns that, see Step 7.)

### Step 7 — Introduce `run`, replacing ad hoc `System/exit` calls deep in the stack

Refactor `handle`/`dispatch` in `cli.clj` so the only side-effecting exit decision lives in `-main`:

```clojure
(defn run
  "Initializes state and dispatches the requested report for `options`.
   Returns nil on success (having already printed the report), or
   {:exit-code int :message string} on failure -- never calls
   System/exit itself, so it can be exercised directly from tests."
  [options]
  (try
    (initialize-state options)
    (dispatch options) ; still returns a violations exit code, see below
  (catch clojure.lang.ExceptionInfo e
    {:exit-code errors/runtime-error-exit-code
     :message (cond-> (errors/friendly-message e)
                (:debug options) (str "\n\n" (errors/debug-details e)))})
  (catch Exception e
    {:exit-code errors/runtime-error-exit-code
     :message (cond-> (str "An unexpected error occurred: " (ex-message e))
                (:debug options) (str "\n\n" (errors/debug-details e)))})))
```

`dispatch` keeps printing the requested report as it does today, but instead of calling `(System/exit 1)` directly for `--fail-on-violations` ([cli.clj:159-160](../../src/sbom_tool/adapter/ui/cli.clj#L159-L160)), it returns `{:exit-code 1 :message nil}` (no extra message needed — the already-printed report is the explanation), or `nil` when there's nothing to report as an exit condition. `run` passes that through unchanged when no exception was thrown.

`-main` becomes the single place that prints an error message (to `*err*`) and exits:

```clojure
(defn -main
  [& args]
  (let [{:keys [options exit-message success]} (validate-args args cli-opts)]
    (if exit-message
      (exit (if success 0 1) exit-message)
      (let [{:keys [exit-code message]} (run options)]
        (when message
          (binding [*out* *err*] (println message)))
        (System/exit (or exit-code 0))))))
```

Justification for pushing `System/exit` to the outermost edge: it is the standard idiom for making Clojure CLI logic testable (`clojure.test` runs in-process; a stray `System/exit` anywhere else would kill the test runner), and it matches this codebase's existing preference (see `exit` already being a thin, dedicated wrapper at [cli.clj:97-99](../../src/sbom_tool/adapter/ui/cli.clj#L97-L99)) — this plan just makes that the *only* place it happens.

### Step 8 — CLI-level tests

Add `test/sbom_tool/adapter/ui/cli_test.clj` (new namespace, doesn't exist today) exercising `run` directly (never `-main`, to avoid `System/exit`):

- A happy-path run against `test/resources/sboms/` returns `nil` (or `{:exit-code 0 ...}`, depending on the final `dispatch` return-value convention chosen in Step 7) and prints a report.
- Running with `:license-policy` pointed at a non-existent file returns `{:exit-code 2 :message "..."}` where the message mentions the path and does not contain a raw stack trace unless `:debug true` was passed.
- Running with `:license-policy` pointed at a syntactically broken EDN fixture returns the same shape with a different message.
- Running with `--fail-on-violations` against SBOMs/policies known to violate returns `{:exit-code 1 ...}`.

Add `test/sbom_tool/adapter/ui/errors_test.clj` for `friendly-message`/`debug-details` directly, covering every `:sbom-tool/error-type` branch plus the `::unknown` fallback, using hand-built `ex-info`s (no I/O needed).

### Step 9 — Documentation

Update [README.md](../../README.md):
- Document exit code `2` alongside the existing `--fail-on-violations` exit-code-1 note.
- Document the new `-d`/`--debug` option in the options table.
- Optionally add a short "Troubleshooting" subsection pointing at `--debug` for anyone filing a bug report.

### Step 10 — Verification

- `lein test` (all new and existing tests green).
- `lein uberjar`, then manually run the built jar against a deliberately broken `-l`/`-V` path and a folder with a malformed `*.cdx.json`, confirming: a one-line, readable message on stderr, exit code `2`, and `--debug` appending the real exception chain.
- Re-run the existing `--fail-on-violations` example from the README to confirm exit code `1` behavior is unchanged.

## File-by-file summary of changes

| File | Change |
|---|---|
| `src/sbom_tool/adapter/ui/errors.clj` | **new** — `friendly-message` multimethod, `debug-details`, `runtime-error-exit-code` |
| `src/sbom_tool/adapter/policies.clj` | tag `validate!`'s `ex-info`; wrap `slurp`/`edn/read-string` via a new `read-edn-file` helper |
| `src/sbom_tool/adapter/sbom/cdx.clj` | wrap `read-json`'s `slurp`/`json/parse-string` |
| `src/sbom_tool/adapter/sbom/spdx.clj` | wrap `read-json`'s `slurp`/`json/parse-string` (identical shape to cdx.clj) |
| `src/sbom_tool/application/repository.clj` | optional: warn on empty glob results in `:cdx`/`:spdx` `read-sboms` methods |
| `src/sbom_tool/domain/vulnerability.clj` | defensive wrap of `LocalDate/parse` in `exemption-expired?` |
| `src/sbom_tool/adapter/ui/cli.clj` | add `-d/--debug` option; fix `validate-args` catch; introduce `run`; slim `-main` |
| `test/sbom_tool/adapter/policies_test.clj` | **new** |
| `test/sbom_tool/adapter/sbom/cdx_test.clj` | **new** |
| `test/sbom_tool/adapter/sbom/spdx_test.clj` | **new** |
| `test/sbom_tool/adapter/ui/errors_test.clj` | **new** |
| `test/sbom_tool/adapter/ui/cli_test.clj` | **new** |
| `test/resources/policies/*.edn` | **new** fixtures (broken EDN, spec-invalid policy) |
| `test/resources/sboms/malformed.cdx.json` (or similar) | **new** fixture |
| `README.md` | document exit code 2 and `--debug` |

## Risks / open questions

- **Cheshire's exact exception class**: confirm at implementation time whether `cheshire.core/parse-string` throws `com.fasterxml.jackson.core.JsonParseException` or the broader `JsonProcessingException` for the malformed-JSON fixtures used in tests, and catch the right one (catching too broad a class here risks masking real bugs, same concern as the OWASP-style guidance against overly broad exception handling).
- **`dispatch`'s return-value contract**: today `dispatch` returns whatever `println` returns (`nil`) and only *sometimes* calls `System/exit` directly. Step 7 changes it to return a `{:exit-code ...}` map (or `nil`) so `run`/`-main` can act on it uniformly — this is a small internal contract change confined to `cli.clj`, not a public API, so it's safe, but implementers should double check every existing call site of `dispatch`/`handle` (currently only `-main` and the `(comment ...)` block at the bottom of `cli.clj`) is updated consistently.
- **Stderr vs stdout for errors**: this plan moves error messages to `*err*` while reports stay on `*out*`, which is standard CLI practice but is a small, technically-observable behavior change for anyone currently scraping stdout for error text; call it out in the PR description.

## Follow-ups (explicitly out of scope here)

- Validating parsed SBOM documents against `sbom-tool.domain.sbom` specs at adapter boundaries (a broader data-integrity project, not just error-message wording).
- Structured (JSON) error output for machine consumers, if a future CI-integration need arises.
