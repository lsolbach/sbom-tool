# Plan: Shared HTTP and Support Namespace for the Vulnerability Adapters

**Status:** implemented
**Date:** 2026-11-13 (revised the same day with the maintainer's answers to the open questions)
**Related:** model decision `:sbom-tool.decision/shared-adapter-support` (proposed, not accepted),
model requirements `:sbom-tool.requirement/bounded-network-calls` and
`:sbom-tool.requirement/credentials-only-to-own-service` (both proposed), model risks
`duplicated-adapter-infrastructure`, `duplicated-bounded-pmap`, `duplicated-warn-helpers`,
`no-network-timeouts-or-size-limits`, `pagination-url-not-pinned-to-host`,
[dev/plans/osv-vulnerability-adapter.md](osv-vulnerability-adapter.md),
[dev/plans/deps-dev-vulnerability-adapter.md](deps-dev-vulnerability-adapter.md),
[dev/plans/github-advisory-vulnerability-adapter.md](github-advisory-vulnerability-adapter.md)
(all implemented, the code this plan refactors),
[dev/plans/nvd-vulnerability-adapter.md](nvd-vulnerability-adapter.md) (proposed, the fourth adapter
that would otherwise add a fourth copy).

## Goals

1. Replace the three copies of the HTTP client, request/error handling, API-key file reading,
   `bounded-pmap`, `warn`, `url-encode` and the `json-processing-exception-class` workaround in
   `adapter/vulnerability/{osv,deps_dev,github_advisory}.clj` with shared code: the HTTP part in
   one adapter-layer namespace (`adapter.http`), the general utilities in `sbom-tool.util.functions`
   (maintainer answer 1). The same `warn` also replaces the private copy in
   the OpenVEX adapter (maintainer answer 3).
2. Fix the two open security findings once, in that namespace:
   - every request has a connect and a request timeout and a response size cap, and a timeout or
     oversize response is a failed lookup (requirement `bounded-network-calls`);
   - an API key (and any request) is sent only to the https host of the service it belongs to, so
     GitHub's `rel="next"` URL is no longer followed blindly (requirement
     `credentials-only-to-own-service`).
3. Keep every observable behavior otherwise unchanged: CLI options, exit codes, report output,
   warning texts, `ex-data` error types and messages (they are consumed by
   `adapter/ui/errors.clj`), result shapes and ordering of the three adapters.
4. Make the NVD adapter plan buildable on the shared namespace from day one.

## Non-goals

- New CLI options (e.g. configurable timeouts or size limit) or changes to exit codes: public
  contracts, Tier 3. Limits are constants in the namespace.
- Retries, rate limiting or HTTP caching.
- Changing the layering: no move to the application layer (decision option 3, rejected).
- Migrating the CycloneDX and SPDX adapters' inline `Warning:` output to the shared `warn` (they
  already write to stderr); see Follow-ups.
- Merging the adapters' mapping logic, caches, purl handling or chunking. Only infrastructure is
  shared.

## Problem

The three adapters each contain a near-identical copy of

| Concern | osv | deps-dev | github-advisory |
|---|---|---|---|
| `json-processing-exception-class` (babashka workaround) | yes | yes | yes |
| `(delay (HttpClient/newHttpClient))`, no timeouts, no size limit | yes | yes | yes |
| build request, `.send`, 2xx check, JSON parse, error wrapping | `send-request`/`fetch-json`/`post-json` | `fetch-json` | `fetch-page` |
| API key file reader (`read-api-key-file`) | yes | none (no key) | yes |
| `warn` to `*err*` | yes | yes | yes |
| `bounded-pmap` | yes | yes | yes |
| `url-encode` | yes | yes | yes |

(The leftover `Fetching URL` debug output was already removed from all three.)

Consequences (see the risks in the model): every cross-cutting fix has to be applied three times
and again for NVD; the default `HttpClient` has no connect or request timeout, so a stalled
endpoint hangs the run; response bodies are read unbounded; the GitHub `Link` next URL is requested
with the `Authorization` bearer token without a scheme or host check.

## Design

### New namespaces

`util` is a folder (`src/sbom_tool/util/`), not a namespace: namespaces added there are leaves.
The general helpers go into one namespace for now, `sbom-tool.util.functions`
(`src/sbom_tool/util/functions.clj`); it can be split into more namespaces in that folder later.
The HTTP code stays in the adapter layer.

| Namespace | File | Contents |
|---|---|---|
| `sbom-tool.util.functions` | `src/sbom_tool/util/functions.clj` | `bounded-pmap` (unchanged fixed-thread-pool implementation, results in input order), `warn` (prints `Warning: <msg>` to `*err*`), `url-encode`, `read-api-key-file` (below) |
| `sbom-tool.adapter.http` | `src/sbom_tool/adapter/http.clj` | `request-json`, `get-json`, `post-json`, the HTTP client and the `json-processing-exception-class` workaround (below) |

Dependency rules (accepted, written into `AGENTS.md`): namespaces in `util` depend on no other
project namespace (leaves) and may be used from any layer; adapter namespaces may depend on each
other as long as no cycle is introduced. `adapter.http` depends only on `util` and external
libraries, never on `application` or `domain`.

`adapter.http` is adapter-internal: only other adapter namespaces require it and it is not wired
into the CLI.

Public functions (no `^:private`, so the adapters can use them; each with a docstring):

A `service` map describes one remote service: `:base-url` (the https origin the requests are
pinned to), `:error-type` (the `:sbom-tool/error-type` of a failed request) and `:service` (its name
in messages).

- `request-json` -- `[service {:keys [method url headers body]}]` -> `{:status n :headers
  {lower-case-name value} :body <parsed JSON, keyword keys>}`.
  - `method` is `:get` or `:post`; `body` (post) is serialized with `json/generate-string` and sent
    with `Content-Type: application/json`.
  - `check-origin!` runs first: the URL must be https with the host and port of `:base-url`,
    otherwise it throws before anything is sent (no key leaves the process). The service's base
    URL is the pin for every call of an adapter, so a pagination URL on another host is rejected
    by the same check.
  - Non-2xx, I/O failure, timeout, oversize body and malformed JSON are all wrapped into an
    `ex-info` tagged with the service's `:error-type` (e.g. `:osv-request-failed`) and the same
    message format as today (`"<service> request to <url> failed with HTTP <status>"`,
    `"... failed: malformed JSON: ..."`), with `:url` and `:status` in `ex-data`.
- `execute-json` -- the same without the origin check; the transport used by `request-json`, public
  so the tests can exercise it against a plain-http loopback server.
- `get-json` / `post-json` -- `[service url headers (body)]`, thin wrappers returning only the
  parsed body, so `deps_dev` and `osv` keep their call shapes; `github-advisory` uses
  `request-json` for the `Link` header.

`util.functions/read-api-key-file` -- `[path {:keys [not-found-error-type malformed-error-type]}]`,
keeping the current messages (`"file not found: <path>"`, `"malformed EDN: ..."`) and `ex-data`
(`:path`, `:sbom-tool/error-type`), so the two `errors.clj` methods for GitHub Advisory continue to
work.

`read-api-key` (file option, else environment variable) and `auth-headers` stay in `osv` and
`github_advisory`: they differ per service (option name, variable name, header name).

### HTTP client, timeouts, size limit

- One shared `HttpClient`, built lazily (`delay`) with `connectTimeout` 10 s and
  `followRedirects NEVER`. A 3xx is a non-2xx failure; a redirect target never receives a key.
  (Today the default client already does not follow redirects; this makes it explicit.)
- Per-request `.timeout` of 30 s.
- Size cap 20 MiB (maintainer decision; connect and request timeouts confirmed). Use `BodyHandlers/ofInputStream`, check `Content-Length` first when present, then
  read at most cap + 1 bytes and fail if exceeded, so memory stays bounded even without a
  `Content-Length` header. `ofString` cannot bound memory, so it is not used.
- The values are constants (not CLI options); the request timeout and the size cap are dynamic
  vars (`*request-timeout*`, `*max-response-bytes*`) so the tests can lower them.
- Verified during planning: `HttpClient$Redirect`, `connectTimeout` and `BodyHandlers/ofInputStream`
  work under babashka (requirement `jvm-and-babashka-portability`). `com.sun.net.httpserver` does
  not, which shapes the tests.

### Error types

Each adapter keeps its own `error-type` keywords, passed into the shared functions. The shared
namespace invents no new error types. The unchanged `ex-data` keeps `ui/errors.clj` and the
adapters' `catch clojure.lang.ExceptionInfo` handlers valid.

### Host pinning for GitHub pagination

`fetch-advisories` passes `:base-url api-base` on every page request, so the `rel="next"` URL is
accepted only when it is `https://api.github.com/...`. A rejected URL throws the usual
`:github-advisory-request-failed`, which the existing chunk handling turns into a warning and an
empty result for that chunk. `parse-link-header` stays as is.

### Alternatives considered

- Keep three copies, fix each (decision option 1): rejected in the proposed decision.
- One single support namespace, as the proposed decision words it: rejected by the maintainer in
  favor of `util` for the general helpers and `adapter.http` for HTTP; the decision text was
  adjusted accordingly when it was accepted.
- Put the HTTP code under `adapter/vulnerability/`: the helper is useful for any future network
  adapter, so `adapter.http` is kept.
- A third-party HTTP library (`clj-http`, `hato`): new dependency and babashka risk for a small
  gain; rejected.

## Step-by-step implementation

0. **Maintainer decision (done 2026-11-13).** `shared-adapter-support` is accepted (text adjusted
   to `util` plus `adapter.http`, `:maturity :proposed` removed) and `AGENTS.md` has the two
   Architecture Rules sentences (adapter dependencies without cycles; `util` namespaces are leaves
   usable from any layer).
1. **Create `util/functions.clj`, `adapter/http.clj` and their tests**
   (`test/sbom_tool/util/functions_test.clj`, `test/sbom_tool/adapter/http_test.clj`). No adapter changes
   yet. Tests as listed in Verification. Run `bb test`.
2. **Migrate deps-dev** (no key, simplest, one call site): replace `http-client`, `fetch-json`,
   `warn`, `bounded-pmap`, `url-encode` and `json-processing-exception-class` with calls into
   `adapter.http` and `util`. Run `bb test`; compare a recorded fetch (existing tests use
   recorded responses, no live calls).
3. **Migrate osv**: also `read-api-key-file`, `post-json`, `send-request`, `build-request`.
4. **Migrate github-advisory**: also `read-api-key-file`; `fetch-page` becomes a call to
   `request-json` that reads the `Link` header from the returned headers, with `:base-url`.
5. **Migrate OpenVEX**: replace its private `warn` with `util.functions/warn` (same output).
6. **Clean up.** `grep` for leftovers of `HttpClient`, `bounded-pmap`, `defn- warn`,
   `json-processing-exception-class` and unused requires/imports under
   `src/sbom_tool/adapter/`; run `bb test`.
7. **README**: document the limits (see File-by-file summary); mention the behavior change
   (open question 1).
8. **Model sync** (see below; Tier 1 for the new elements, Tier 2 for removed risks, Tier 3 for the
   decision and requirement status, which the maintainer applies).
9. **Update the NVD plan** with a short note that it uses `adapter.http` and `util` instead of
   adding its own client, `warn` and pool (Design only, no scope change).
10. **Plan status** to `implemented` only when the maintainer says so, on the evidence in
   Verification.

## File-by-file summary

| File | Change |
|---|---|
| `src/sbom_tool/util/functions.clj` | New: `bounded-pmap`, `warn`, `url-encode`, `read-api-key-file` |
| `src/sbom_tool/adapter/http.clj` | New: HTTP client, `request-json`/`get-json`/`post-json`, timeouts, size cap, host pinning |
| `src/sbom_tool/adapter/vulnerability/deps_dev.clj` | Remove HTTP client, `fetch-json`, `warn`, `bounded-pmap`, `url-encode`, exception-class workaround; call `adapter.http` and `util` |
| `src/sbom_tool/adapter/vulnerability/osv.clj` | Same, plus `read-api-key-file`, `send-request`, `build-request`, `post-json` |
| `src/sbom_tool/adapter/vulnerability/github_advisory.clj` | Same, plus `fetch-page` rewritten on `request-json`; `:base-url` pins pagination |
| `src/sbom_tool/adapter/vex/openvex.clj` | Replace private `warn` with `util.functions/warn` |
| `test/sbom_tool/util/functions_test.clj`, `test/sbom_tool/adapter/http_test.clj` | New |
| `test/sbom_tool/adapter/vulnerability/*_test.clj` | Unchanged unless they reference a removed private var (they currently do not) |
| `README.md` | New paragraph under "Live vulnerability lookups" (see below) |
| `AGENTS.md` | Two sentences in Architecture Rules (maintainer, step 0) |
| `models/sbom-tool/code.edn` | New `:namespace` elements for `util.functions` and `adapter.http` with `:contained-in` and `:dependency` relations from the adapters (same pattern as the existing `...-depends-on-...` relations); `util` gets its own package contained in the code root |
| `models/sbom-tool/risks.edn`, `decisions.edn`, `requirements.edn` | Risks resolved, decision and requirements status (see Model changes) |
| `dev/plans/nvd-vulnerability-adapter.md` | Design note, step 9 |

### README text (step 7)

A paragraph at the start of "Live vulnerability lookups", valid for all sources, stating: every
live request has a 10 second connect timeout and a 30 second request timeout; a response larger
than 20 MiB is rejected; requests, and API keys, are sent only over HTTPS to the host of the
selected service (a pagination link to another host is refused, redirects are not followed); and
a request that exceeds a limit counts as a failed lookup, i.e. a warning on stderr, no additional
vulnerabilities for the affected components, and the run continues (so a run that used to hang on
a stalled endpoint now finishes). The limits are fixed, not configurable.

## Model changes

| Change | Tier | Who |
|---|---|---|
| Accept `shared-adapter-support` (`:maturity :proposed` removed, Status section updated) | 3 | Maintainer |
| Accept `bounded-network-calls` and `credentials-only-to-own-service` (remove `:proposed`) | 3 | Maintainer |
| Add the namespaces `sbom-tool.code.adapter/http` and `sbom-tool.util.functions` with their `:contained-in` and `:dependency` relations (including a `util` package contained in the code root); check views that show the code model (`--select-views`) | 1 | Agent, after approval |
| Remove the resolved risks `duplicated-adapter-infrastructure`, `duplicated-bounded-pmap`, `no-network-timeouts-or-size-limits`, `pagination-url-not-pinned-to-host` with their `:risk-for` relations, as was done for `debug-println-to-stdout`. Also remove `duplicated-warn-helpers`: the OpenVEX adapter is included, so no private `warn` remains in the vulnerability or VEX adapters | 2 | Agent, after approval |
| Update references to the removed risks in descriptions (e.g. in `decisions.edn`) | 0 | Agent |
| Accept the decision with the text adjusted to `util` plus `adapter.http` (see step 0) | 3 | Maintainer, **done 2026-11-13** |
| Validate: `java -jar tools/overarch.jar -m models -S '{:namespace-prefix "sbom-tool"}'` | | |

No change to goals, constraints or public contracts. `bounded-concurrent-lookups` stays as written
(its consequence about duplication is superseded by the accepted decision, as the decision states).

## Verification

Automated (`bb test`; tests mirror the source namespace):

- `adapter/http_test.clj` for `request-json`: 2xx with JSON body; non-2xx wraps into the given
  `error-type` with `:status` and `:url`; malformed JSON; I/O failure; oversize body (via
  `Content-Length` and via chunked body without it); connect/request timeout (e.g. a
  `java.net.ServerSocket` that accepts and never answers, with a short timeout through a dynamic
  var; if `ServerSocket` is not available under babashka, replace the I/O with `with-redefs` of the
  send function and assert the timeout is set on the built request); a 3xx response is a failure
  and is not followed; `:base-url` rejects `http://`, another host and a lookalike host
  (`api.github.com.evil.example`) without sending a request; the key header is absent from the
  rejected request.
- `util.functions/read-api-key-file`: ok, not found, malformed EDN, with the caller's error types and the existing
  messages.
- `util.functions/bounded-pmap`: results in input order, never more than `n` concurrent tasks, an exception in a
  task surfaces.
- `util.functions/warn`: writes to `*err*`, nothing to `*out*`; `util.functions/url-encode`: reserved characters and spaces. The OpenVEX adapter's existing tests still pass.
- `github_advisory_test.clj`: a Link header pointing to another host is rejected and does not
  abort the whole run (chunk-level warning and empty result), if `fetch-advisories` can be exercised
  with a `with-redefs` of the new send seam.
- Existing adapter tests, `errors_test.clj` and `cli_test.clj` pass unchanged (behavior preserved).
- Run `bb test` under both runtimes the project supports (requirement
  `jvm-and-babashka-portability`); `bb test` itself is babashka. If a JVM test run is available in
  the environment (`lein test`), run it too.

Manual (maintainer, needs network and optionally keys):

- `--vulnerability-source osv|deps-dev|github-advisory` against a small real SBOM produces the same
  report as before the refactoring (diff of the JSON report).
- Block the endpoint (e.g. a firewall rule or a local non-answering listener on a configured base
  URL) and confirm the run ends with a warning after the timeout instead of hanging.

README: the paragraph states the limits listed in this plan (10 s, 30 s, 20 MiB).

Model: validation command above reports empty `:build-problems`, `:unresolved-refs-in-views` and
`:unresolved-refs-in-relations`.

## Implementation progress (2026-11-13)

Steps 1-9 are done; the plan status stays `proposed` until the maintainer sets it.

Evidence: `bb test` and `lein -o test` both pass (127 tests, 525 assertions, 0 failures) including
the new `util/functions_test.clj`, `adapter/http_test.clj` (a loopback server on a `ServerSocket`
covers 2xx, non-2xx, malformed JSON, connection failure, redirect, POST body and headers, timeout,
oversize with and without `Content-Length`) and the pagination test in
`github_advisory_test.clj`. A run of the CLI with `-D osv`, `-D deps-dev` and `-D github-advisory`
against the real services on a one-component SBOM returned vulnerabilities for all three. The
model validates with empty `:build-problems`, `:unresolved-refs-in-views` and
`:unresolved-refs-in-relations`. The README paragraph is in place.

Deviations from the plan text above:

- `duplicated-warn-helpers` was narrowed, not removed: the CycloneDX and SPDX adapters still print
  their warnings inline (a follow-up below), so the risk now describes only that.
- The accepted decision's Context section still names the removed risks as history; accepted
  decisions are not edited in place.
- The requirements `bounded-network-calls` and `credentials-only-to-own-service` are still
  `:proposed` (the maintainer accepts them); their Measure text now states the implemented values
  and that they are met.
- Not verified: the stall behavior against a real stalled endpoint (only the loopback test).

## Risks / open questions

Answered by the maintainer on 2026-11-13 (recorded here, reflected above): (1) general utilities go
to `util`, the HTTP code stays in `adapter.http`; (2) timeouts confirmed, size cap 20 MiB;
(3) OpenVEX is included; (4) the limits are documented in the README; (7) adapter namespaces may
depend on each other as long as no cycles are introduced; (follow-up questions) `util` is the
folder `src/sbom_tool/util/`, its namespaces are leaves that any layer may use, the first one is
`sbom-tool.util.functions`, and the folder gets its own package in `code.edn`. The decision was
accepted and `AGENTS.md` updated the same day (step 0).

1. **Behavior change: failure instead of hang.** A request that used to hang forever, or a huge
   response that used to be accepted, now becomes a failed lookup (warning, empty result, run
   continues). Intended by the requirement and documented in the README (step 7).
2. **Size cap per response, not per run.** 20 MiB per response; a very large SBOM with many large
   GitHub or OSV pages is the case to watch.
3. **Babashka:** the planning check covered the client builder, redirect policy and
   `ofInputStream`. The timeout and size-limit behavior under babashka is verified only when step 1
   runs; if `ofInputStream` reading differs, fall back to checking `Content-Length` plus a
   bounded read loop.
4. **Refactoring without HTTP-level tests today.** The adapters' tests use recorded data and never
   perform requests, so regressions in the migrated call sites are caught only by the new tests and
   the manual comparison. Keep the migration one adapter per commit to ease review.
5. **Dependency cycles.** The agreed rule allows adapter-to-adapter dependencies without cycles.
   Nothing enforces it; `adapter.http` is a leaf of the adapter layer, and a `:dependency` check in
   the code model (step 8) is the only guard.
## Follow-ups (explicitly out of scope here)

- Move the inline `Warning:` output of the CycloneDX and SPDX adapters (`binding [*out* *err*]`
  plus `println`) onto `util.functions/warn`.
- A shared `--debug` diagnostic function for request tracing (the former `Fetching URL` output,
  stderr only, behind `--debug`).
- Configurable timeout and size limit as CLI or policy options (public contract change, Tier 3).
- Optional retry with backoff for HTTP 429/5xx once real-world use shows the need.
