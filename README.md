# SBOM Tool
The SBOM Tool reads software bill of material (SBOM) files and reports on them.
It currently supports CycloneDX 1.6 (`*.cdx.json`) and SPDX 2.2/2.3 (`*.spdx.json`) files.

## Usage
The SBOM Tool is written in Clojure.

Run with [Leiningen](https://leiningen.org/):

```
lein run -- -I sboms -l example-license-policy.edn
```

Or build and run an uberjar:

```
lein uberjar
java -jar target/sbom-tool.jar -I sboms -l example-license-policy.edn
```

Or run with [babashka](https://babashka.org/):

```
sbom-tool -I sboms -l example-license-policy.edn
```

To gate a CI pipeline on blacklisted licenses or policy-blocked vulnerabilities, add
`--fail-on-violations` (the process exits with status 1 if any are found, regardless of
which `--report` was requested):

```
sbom-tool -I sboms \
   -l example-license-policy.edn -V example-vulnerability-policy.edn \
   -r all --fail-on-violations
```

For a human-readable summary (e.g. to paste into a PR or CI job summary), render as markdown:

```
sbom-tool -I sboms -r all-license -o markdown
```

Or, for consumption by other tooling, render as JSON:

```
sbom-tool -I sboms -r all-license -o json
```

### Options

| Option                              | Default    | Description                        |
|-------------------------------------|------------|-------------------------------------|
| `-I, --input-path PATH`             | `sboms`    | Folder containing the SBOM files    |
| `-s, --sbom-format FORMAT`          | `:auto`    | SBOM format to read: `:auto` (every `*.cdx.json` and `*.spdx.json` file), `:cdx` or `:spdx` |
| `-m, --merge-unidentified`          | `false`    | Also merge components across documents that carry neither a purl nor a cpe, by name/version alone (see "Multi-format consolidation" below) |
| `-D, --vulnerability-source SOURCE` | `:none`    | Source for live vulnerability lookups keyed by component purl: `:none` (fully offline), `:deps-dev` (see "Live vulnerability lookups (deps.dev)" below), `:github-advisory` (see "Live vulnerability lookups (GitHub Advisory Database)" below) or `:osv` (see "Live vulnerability lookups (OSV)" below) |
| `-G, --github-advisory-api-key-file PATH` | —    | EDN file providing `{:api-key "..."}` for GitHub Advisory Database API requests; optional (the endpoint answers unauthenticated requests), falls back to the `GITHUB_ADVISORY_API_KEY` environment variable; raises the rate limit from 60 to 5000 requests/hour |
| `-K, --osv-api-key-file PATH`       | —          | EDN file providing `{:api-key "..."}` for OSV API requests; optional, falls back to the `OSV_API_KEY` environment variable; OSV's public API currently requires neither |
| `-X, --vex-path PATH`               | —          | Folder containing OpenVEX documents (`*.vex.json`) to apply to vulnerability reports (see "VEX (OpenVEX)" below); optional, no VEX is applied unless given |
| `-l, --license-policy PATH`         | —          | EDN license policy file (see [example-license-policy.edn](example-license-policy.edn)); falls back to the bundled default policy |
| `-V, --vulnerability-policy PATH`   | —          | EDN vulnerability policy file (see [example-vulnerability-policy.edn](example-vulnerability-policy.edn)); falls back to the bundled default policy |
| `-L, --spdx-license-list PATH`      | —          | SPDX license list JSON file (`json/licenses.json` from [spdx/license-list-data](https://github.com/spdx/license-list-data)); falls back to a bundled snapshot |
| `-r, --report REPORT`               | `all-license` | Report to generate: `licenses`, `license-status-summary`, `license-summary`, `multi-licensed`, `unidentified-licenses`, `blacklisted-licenses`, `copyright`, `missing-copyright`, `vulnerabilities`, `vulnerability-summary`, `blocked-vulnerabilities`, `all-license` (every license report, which includes both copyright reports), `all-copyrights` (just the copyright reports), `all-vulnerabilities` (every vulnerability report) or `all` (all of the above) |
| `-o, --output-format FORMAT`        | `edn`      | Output format: `edn`, `json` or `markdown` |
| `-f, --fail-on-violations`          | `false`    | Exit with status 1 if there are blacklisted licenses or policy-blocked vulnerabilities |
| `-d, --debug`                       | `false`    | On failure, append the full exception cause chain to the error message, for troubleshooting |
| `-h, --help`                        | —          | Print usage                         |

### Exit codes

| Code | Meaning |
|------|---------|
| `0`  | Success |
| `1`  | A CLI usage error (bad/missing arguments, `--help`), or `--fail-on-violations` found a blacklisted license or a policy-blocked vulnerability |
| `2`  | A runtime/data error: an SBOM or policy file could not be read or parsed, or a report could not be rendered |

### Troubleshooting

If the tool exits with a message you don't understand, rerun with `-d`/`--debug` to append
the full exception cause chain (down to the original I/O or parse error) to the printed
message.

**Disclaimer**: The vulnerability reports rely on the information contained in the SBOM files and only report the vulnerabilities known at the time the SBOMs were created.
When the SBOMs do not contain vulnerability information, no vulnerabilities are reported -- which reads as "no known vulnerabilities" even though the truth is "no data".
Because of this, the default report (`all-license`) omits vulnerability reports; request `all-vulnerabilities` or `all` explicitly once your SBOMs are known to carry vulnerability data.
Opting into `-D deps-dev`, `-D github-advisory` or `-D osv` (see below) supplements this with live lookups, but only for components identified by purl -- it does not replace SBOM-embedded data, and each is itself just one vulnerability database among several.
Opting into `-X`/`--vex-path` (see "VEX (OpenVEX)" below) can suppress a false positive for a component a supplier has assessed as not actually exploitable, but only for the exact product(s) a matching VEX statement names -- it does not change any other component's report.

**The SBOM Tool should not be treated as the only measure for vulnerability checks.**

### Policy files

Both policy files are plain EDN and fall back to a bundled default (`resources/policy/`) when
not given via `-l`/`-V`.

**License policy** (see [example-license-policy.edn](example-license-policy.edn)) — a map keyed
by component type (`:default`, `:library`, ...; `:default` applies to any type without its own
entry), each with:
- `:whitelist` — license ids considered safe to use without further review.
- `:blacklist` — license ids (copyleft) that must not be used; these drive `blacklisted-licenses`
  and `--fail-on-violations`.
- Any license that is neither whitelisted nor blacklisted is reported as greylisted, requiring
  manual review.

Two further keys sit alongside the component-type buckets, global rather than per-type, each a
set of component matchers -- a bare component name, a `{:name ... :version ...}` map narrowing
the match to an exact version, or a `{:purl ...}` map matching by purl:
- `:proprietary` — components known to be closed source; reported with a `proprietary` status
  instead of "no license", since their total absence of license metadata is expected, not a data
  gap.
- `:reviewed` — components whose license situation (greylisted, unidentified, or no license at
  all) has already been manually checked and accepted; reported with a `reviewed` status instead.
  `:reviewed` never overrides a `:blacklist` match -- a blacklisted license stays blocked
  regardless.

Neither `:proprietary` nor `:reviewed` counts as a policy violation for `--fail-on-violations`.

**Vulnerability policy** (see [example-vulnerability-policy.edn](example-vulnerability-policy.edn))
— a map with:
- `:max-severity` — the lowest severity (`:unknown`, `:low`, `:medium`, `:high` or `:critical`)
  that fails the policy gate; vulnerabilities at or above it are `:blocked` (driving
  `blocked-vulnerabilities` and `--fail-on-violations`), unless exempted. `nil` disables severity
  gating entirely.
- `:ignored` — a map of accepted-risk vulnerability id (e.g. CVE id) to exemption, for findings
  that are reviewed and accepted as risk, e.g. because no fix is available yet. Each exemption
  may carry an optional `:justification` (free text) and an optional `:expiry-date` (ISO-8601
  date); once past, the exemption stops applying and the vulnerability is evaluated normally
  again. A legacy bare id set (e.g. `#{"CVE-2021-12345"}`) is still accepted, as exemptions that
  never expire.

### SPDX license list

Each license in a `licenses` report entry carries four explicit fields: `:license-id` (its raw
identifier, e.g. `"MIT"`), `:license-name` (its SPDX-canonical name, e.g. `"MIT License"`),
`:license-url` (the official SPDX license detail page, e.g.
`"https://spdx.org/licenses/MIT.html"`) and `:status` (its policy status: `:white`, `:black`,
`:grey`, or `:proprietary`/`:no-license`/`:reviewed` per the license policy's `:proprietary`/
`:reviewed` keys, see "Policy files" above).
`:license-name`/`:license-url` are resolved against the SPDX license list (`json/licenses.json`
from [spdx/license-list-data](https://github.com/spdx/license-list-data)) whenever `:license-id`
is a single id directly recognized by it, and are `nil` otherwise -- e.g. for a compound
`AND`/`OR` expression or a custom `LicenseRef-` id, neither of which has a single canonical name
or detail page. A snapshot of the list ships bundled with the tool; pass `-L`/`--spdx-license-list`
to use a different (e.g. newer) one instead.

In the `markdown` output format, the License Name column links to `:license-url` when known, so a
reader can click straight through to the license text.

### Live vulnerability lookups

By default, the tool is fully offline: vulnerability reports only ever contain what the SBOM
documents themselves declared (see the disclaimer above).

Live lookups can be enabled with the `-D` flag.

#### deps.dev

Passing `-D deps-dev`/
`--vulnerability-source deps-dev` opts into supplementing that with live lookups against Google
[deps.dev](https://deps.dev), keyed by each consolidated component's purl -- deps.dev has no
cpe or name/version-only lookup, so components identified only by cpe, or not identified at all,
get no enrichment from this. This makes network calls to `https://api.deps.dev`, requires no API
key, and its findings flow through the same `vulnerability` report, `vulnerability-summary`,
`blocked-vulnerabilities` and `--fail-on-violations` gating as SBOM-embedded ones -- they show up
identically, just with `"deps.dev"` as their `:source`.

A failed lookup (network error, an unrecognized purl type, or an advisory with no usable id)
never aborts the run: it is logged as a warning on stderr and treated as "no additional
vulnerabilities for this component," so the rest of the report is unaffected.

#### GitHub Advisory Database

Passing `-D github-advisory`/`--vulnerability-source github-advisory` opts into supplementing SBOM-
embedded vulnerability data with live lookups against GitHub's [Advisory
Database](https://github.com/advisories), keyed by each consolidated component's purl -- like
deps.dev, components identified only by cpe, or not identified at all, get no enrichment from this.
Unlike deps.dev, it also covers Composer/Packagist packages. This makes network calls to
`https://api.github.com`, batched by ecosystem (one or a few requests per distinct ecosystem
present in the SBOMs, not one per component) rather than one call per purl. A GitHub token is
optional -- the endpoint answers unauthenticated requests, at 60 requests/hour -- but raises the
rate limit to 5000/hour; supply one via `-G`/`--github-advisory-api-key-file` (an EDN file shaped
`{:api-key "..."}`, never committed to the repo) or the `GITHUB_ADVISORY_API_KEY` environment
variable. Its findings flow through the same `vulnerability` report, `vulnerability-summary`,
`blocked-vulnerabilities` and `--fail-on-violations` gating as SBOM-embedded ones -- they show up
identically, just with `"GitHub Advisory Database"` as their `:source`.

A failed lookup (network error, an unrecognized purl type, or an advisory with no usable id) never
aborts the run: it is logged as a warning on stderr and treated as "no additional vulnerabilities
for the affected components", so the rest of the report is unaffected.

#### OSV

Passing `-D osv`/`--vulnerability-source osv` opts into supplementing SBOM-embedded vulnerability
data with live lookups against Google [OSV](https://osv.dev), keyed by each consolidated
component's purl -- like deps.dev and GitHub Advisory Database, components identified only by cpe,
or not identified at all, get no enrichment from this. This makes network calls to
`https://api.osv.dev`: every distinct, versioned purl is resolved to its vulnerability ids in a
handful of batched `querybatch` requests, and only the *distinct* ids referenced across the whole
run are then each fetched once. No API key is required today -- OSV's public API is unauthenticated
-- but one can be supplied for forward compatibility (or a self-hosted/gated OSV-compatible
endpoint) via `-K`/`--osv-api-key-file` (an EDN file shaped `{:api-key "..."}`, never committed to
the repo) or the `OSV_API_KEY` environment variable. Its findings flow through the same
`vulnerability` report, `vulnerability-summary`, `blocked-vulnerabilities` and
`--fail-on-violations` gating as SBOM-embedded ones -- they show up identically, just with
`"OSV"` as their `:source`. Severity prefers a record's `database_specific.severity` (GHSA's own
qualitative rating, populated by a large share of OSV's aggregated sources); when that is absent,
it falls back to computing a CVSS v3 Base Score from a `CVSS_V3` vector in the record's `severity[]`
(some Maven/Debian/Alpine-sourced OSV entries only carry this), then to a CVSS v2 Base Score from a
`CVSS_V2` vector (using CVSS v2's own three-band Low/Medium/High scale, which has no "Critical") --
`:unknown` only when none of the three is present.

A failed lookup (network error, an unversioned/unsupported purl, or a record with no usable id)
never aborts the run: it is logged as a warning on stderr and treated as "no additional
vulnerabilities for the affected components," so the rest of the report is unaffected.

### VEX (OpenVEX)

Passing `-X PATH`/`--vex-path PATH` reads every [OpenVEX](https://github.com/openvex/spec)
document (`*.vex.json`) under `PATH` -- typically one per supplier -- and applies their
`statements` to the `vulnerabilities` report and `blocked-vulnerabilities`/`--fail-on-violations`
gating, matched by each statement's vulnerability id (or alias) and product purl/cpe against the
consolidated component being reported. A `not_affected` or `fixed` statement is authoritative:
it downgrades that vulnerability's status (shown as `not affected (VEX)`/`fixed (VEX)`, with the
`not_affected` justification, e.g. `vulnerable_code_not_present`, when given) and excludes it from
`blocked-vulnerabilities`/`--fail-on-violations` for the product(s) it names -- but only once
*every* consolidated component the vulnerability affects has such a statement; if it still affects
even one component with no matching statement, it stays blocked for the whole report. An
`affected` or `under_investigation` statement is shown alongside the vulnerability as an
annotation only and never changes its policy status. When more than one document's statements
disagree on the same vulnerability+product, the more conservative status wins (`affected` >
`under_investigation` > `fixed` > `not_affected`), so one stale or overly-optimistic
`not_affected` claim can never suppress another document's genuine `affected` one.

This is a purely local, offline read -- unlike `-D`/`--vulnerability-source`, no network calls
are made. Unlike those live lookups, a malformed VEX file under `PATH` fails the run (the same
treatment as a malformed SBOM file), since it is as much "your input" as an SBOM; a `PATH` with
no `*.vex.json` files at all only warns.

### Multi-format consolidation

With the default `-s :auto`, a folder mixing CycloneDX and SPDX files describing the same
package (matched by `purl`, falling back to `cpe`) is reported as a single, consolidated
component carrying the union of both documents' data — e.g. CycloneDX-reported vulnerabilities
together with SPDX's `concluded`/`from-files` license detail for the same library. Every
component-based report entry (`licenses`, `multi-licensed`, `unidentified-licenses`,
`blacklisted-licenses`, `copyright`, `missing-copyright`, `vulnerabilities`) carries a `:sources` field listing which document
formats it was assembled from, and, when the source documents genuinely disagreed on a scalar
field (e.g. two different `description`s), a `:conflicts` field listing the values that lost
out — the `markdown` renderer only shows `:sources` as a column; `:conflicts` is visible in the
`edn`/`json` output.

Components that carry neither a `purl` nor a `cpe` are, by default, never merged across
documents — matching them by name/version alone is a heuristic that can wrongly combine
unrelated packages that happen to share both (plausible across ecosystems, e.g. a Python and an
npm package both called `requests`). Pass `-m`/`--merge-unidentified` to opt into that fallback
matching anyway.

## Copyright
© 2026 Ludger Solbach

## License
Eclipse Public License 1.0 (EPL1.0)