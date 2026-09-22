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
| `-l, --license-policy PATH`         | —          | EDN license policy file (see [example-license-policy.edn](example-license-policy.edn)); falls back to the bundled default policy |
| `-V, --vulnerability-policy PATH`   | —          | EDN vulnerability policy file (see [example-vulnerability-policy.edn](example-vulnerability-policy.edn)); falls back to the bundled default policy |
| `-L, --spdx-license-list PATH`      | —          | SPDX license list JSON file (`json/licenses.json` from [spdx/license-list-data](https://github.com/spdx/license-list-data)); falls back to a bundled snapshot |
| `-r, --report REPORT`               | `all-license` | Report to generate: `licenses`, `license-status-summary`, `license-summary`, `multi-licensed`, `unidentified-licenses`, `blacklisted-licenses`, `vulnerabilities`, `vulnerability-summary`, `blocked-vulnerabilities`, `all-license` (every license report), `all-vulnerabilities` (every vulnerability report) or `all` (both) |
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
`"https://spdx.org/licenses/MIT.html"`) and `:status` (its whitelist/blacklist status).
`:license-name`/`:license-url` are resolved against the SPDX license list (`json/licenses.json`
from [spdx/license-list-data](https://github.com/spdx/license-list-data)) whenever `:license-id`
is a single id directly recognized by it, and are `nil` otherwise -- e.g. for a compound
`AND`/`OR` expression or a custom `LicenseRef-` id, neither of which has a single canonical name
or detail page. A snapshot of the list ships bundled with the tool; pass `-L`/`--spdx-license-list`
to use a different (e.g. newer) one instead.

In the `markdown` output format, the License Name column links to `:license-url` when known, so a
reader can click straight through to the license text.

### Multi-format consolidation

With the default `-s :auto`, a folder mixing CycloneDX and SPDX files describing the same
package (matched by `purl`, falling back to `cpe`) is reported as a single, consolidated
component carrying the union of both documents' data — e.g. CycloneDX-reported vulnerabilities
together with SPDX's `concluded`/`from-files` license detail for the same library. Every
component-based report entry (`licenses`, `multi-licensed`, `unidentified-licenses`,
`blacklisted-licenses`, `vulnerabilities`) carries a `:sources` field listing which document
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