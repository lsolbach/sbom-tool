# SBOM Tool
The SBOM Tool reads software bill of material (SBOM) files and reports on them.
It currently supports CycloneDX 1.6 (`*.cdx.json`) and SPDX 2.2/2.3 (`*.spdx.json`) files.

It reports on
- the licenses of the components, checked against a configurable license policy (whitelist, blacklist, greylist),
- their copyright information,
- their vulnerabilities, checked against a configurable vulnerability policy, optionally supplemented by live lookups (deps.dev, GitHub Advisory Database, OSV) and OpenVEX statements,

in `edn`, `json` or `markdown` format, and can fail a CI pipeline on policy violations.

**Disclaimer**: The license reports rely on the information contained in the SBOM files and only report the licenses known to the SBOM's producer when it added the license data.

**Disclaimer**: The vulnerability reports rely on the information contained in the SBOM files and
only report the vulnerabilities known to the SBOM's producer when it added the vulnerability data.
When the SBOMs do not contain vulnerability information (e.g. SPDX files don't carry it),
no vulnerabilities are reported, which reads as "no known vulnerabilities" even though the
truth is "no data".
**The SBOM Tool should not be treated as the only measure for vulnerability checks.**

## Quick start
The SBOM Tool is written in Clojure. Run it with [Leiningen](https://leiningen.org/):

```
lein run -- -I sboms -l example-license-policy.edn
```

Or build and run an uberjar:

```
lein uberjar
java -jar target/sbom-tool.jar -I sboms -l example-license-policy.edn
```

Or run it with [babashka](https://babashka.org/):

```
sbom-tool -I sboms -l example-license-policy.edn
```

To gate a CI pipeline on blacklisted licenses or policy-blocked vulnerabilities, add `--fail-on-violations`:

```
sbom-tool -I sboms -l example-license-policy.edn -V example-vulnerability-policy.edn -r all --fail-on-violations
```

`sbom-tool --help` lists all options. The [usage documentation](docs/usage.md) describes the options, exit codes, policy files, live vulnerability lookups, VEX support and multi-format consolidation.

## Options

| Option                              | Default    | Description                        |
|-------------------------------------|------------|-------------------------------------|
| `-I, --input-path PATH`             | `sboms`    | Folder containing the SBOM files    |
| `-s, --sbom-format FORMAT`          | `:auto`    | SBOM format to read: `:auto` (every `*.cdx.json` and `*.spdx.json` file), `:cdx` or `:spdx` |
| `-m, --merge-unidentified`          | `false`    | Also merge components across documents that carry neither a purl nor a cpe, by name/version alone (see "Multi-format consolidation" below) |
| `-D, --vulnerability-source SOURCE` | `:none`    | Source for live vulnerability lookups keyed by component purl: `:none` (fully offline), `:deps-dev` (see "Live vulnerability lookups (deps.dev)" below), `:github-advisory` (see "Live vulnerability lookups (GitHub Advisory Database)" below) or `:osv` (see "Live vulnerability lookups (OSV)" below) |
| `-G, --github-advisory-api-key-file PATH` | —    | EDN file providing `{:api-key "..."}` for GitHub Advisory Database API requests; optional (the endpoint answers unauthenticated requests), falls back to the `GITHUB_ADVISORY_API_KEY` environment variable; raises the rate limit from 60 to 5000 requests/hour |
| `-K, --osv-api-key-file PATH`       | —          | EDN file providing `{:api-key "..."}` for OSV API requests; optional, falls back to the `OSV_API_KEY` environment variable; OSV's public API currently requires neither |
| `-X, --vex-path PATH`               | —          | Folder containing OpenVEX documents (`*.vex.json`) to apply to vulnerability reports (see "VEX (OpenVEX)" below); optional, no VEX is applied unless given |
| `-l, --license-policy PATH`         | —          | EDN license policy file (see [example-license-policy.edn](../example-license-policy.edn)); falls back to the bundled default policy |
| `-V, --vulnerability-policy PATH`   | —          | EDN vulnerability policy file (see [example-vulnerability-policy.edn](../example-vulnerability-policy.edn)); falls back to the bundled default policy |
| `-L, --spdx-license-list PATH`      | —          | SPDX license list JSON file (`json/licenses.json` from [spdx/license-list-data](https://github.com/spdx/license-list-data)); falls back to a bundled snapshot |
| `-r, --report REPORT`               | `all-license` | Report to generate: `licenses`, `license-status-summary`, `license-summary`, `multi-licensed`, `unidentified-licenses`, `blacklisted-licenses`, `copyright`, `missing-copyright`, `vulnerabilities`, `vulnerability-summary`, `blocked-vulnerabilities`, `all-license` (every license report, which includes both copyright reports), `all-copyrights` (just the copyright reports), `all-vulnerabilities` (every vulnerability report) or `all` (all of the above) |
| `-o, --output-format FORMAT`        | `edn`      | Output format: `edn`, `json` or `markdown` |
| `-f, --fail-on-violations`          | `false`    | Exit with status 1 if there are blacklisted licenses or policy-blocked vulnerabilities |
| `-d, --debug`                       | `false`    | On failure, append the full exception cause chain to the error message, for troubleshooting |
| `-h, --help`                        | —          | Print usage                         |

## Exit codes

| Code | Meaning |
|------|---------|
| `0`  | Success (including `--help`) |
| `1`  | `--fail-on-violations` found a blacklisted license or a policy-blocked vulnerability, for usage in CI/CD |
| `2`  | A runtime/data error: an SBOM or policy file could not be read or parsed, or a report could not be rendered |
| `3`  | A CLI usage error: bad or missing arguments |


## Copyright
© 2026 Ludger Solbach

## License
Eclipse Public License 1.0 (EPL1.0)