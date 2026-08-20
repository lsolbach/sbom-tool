# SBOM Tool
Reads software bill of material (SBOM) files and reports on them.

Supports CycloneDX 1.6 (`*.cdx.json`) and SPDX 2.2 (`*.spdx.json`) files.

## Usage

Run with Leiningen:

```
lein run -- -I sboms -s cdx -l example-license-policy.edn
```

Or build and run an uberjar:

```
lein uberjar
java -jar target/sbom-tool.jar -I sboms -s cdx -l example-license-policy.edn
```

Or run with [babashka](https://babashka.org/):

```
bb -m sbom-tool.adapter.ui.cli -I sboms -s cdx -l example-license-policy.edn
```

To gate a CI pipeline on blacklisted licenses or policy-blocked vulnerabilities, add
`--fail-on-violations` (the process exits with status 1 if any are found, regardless of
which `--report` was requested):

```
bb -m sbom-tool.adapter.ui.cli -I sboms -s cdx \
   -l example-license-policy.edn -V example-vulnerability-policy.edn \
   -r all --fail-on-violations
```

For a human-readable summary (e.g. to paste into a PR or CI job summary), render as markdown:

```
bb -m sbom-tool.adapter.ui.cli -I sboms -s cdx -r all -o markdown
```

### Options

| Option                              | Default    | Description                        |
|-------------------------------------|------------|-------------------------------------|
| `-I, --input-path PATH`             | `sboms`    | Folder containing the SBOM files    |
| `-s, --sbom-format FORMAT`          | `:cdx`     | SBOM format: `:cdx` or `:spdx`      |
| `-l, --license-policy PATH`         | —          | EDN license policy file (see [example-license-policy.edn](example-license-policy.edn)); falls back to the bundled default policy |
| `-V, --vulnerability-policy PATH`   | —          | EDN vulnerability policy file (see [example-vulnerability-policy.edn](example-vulnerability-policy.edn)); falls back to the bundled default policy |
| `-r, --report REPORT`               | `licenses` | Report to generate: `licenses`, `license-summary`, `multi-licensed`, `unidentified-licenses`, `blacklisted-licenses`, `vulnerabilities`, `vulnerability-summary`, `blocked-vulnerabilities` or `all` |
| `-o, --output-format FORMAT`        | `edn`      | Output format: `edn` or `markdown` |
| `-f, --fail-on-violations`          | `false`    | Exit with status 1 if there are blacklisted licenses or policy-blocked vulnerabilities |
| `-h, --help`                        | —          | Print usage                         |


