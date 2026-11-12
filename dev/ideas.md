# Ideas

## SPDX Licenses
* Read SPDX license information as JSON from
  * Github repo -- fetch/refresh the snapshot from spdx/license-list-data at runtime, instead of
    only reading a local file or the bundled snapshot
* Use the SPDX license information in license reports
  * flag deprecated SPDX license ids (`isDeprecatedLicenseId`) distinctly from unidentified ones
    (the list is already read with a `:deprecated?` flag, but no report uses it yet)
  * use the license list as the source of truth for `license/spdx-identifiable?`, instead of the
    current `LicenseRef-` heuristic

## Vulnerability Database Adapters
* Read current vulnerability information from NVD (planned, see
  [dev/plans/nvd-vulnerability-adapter.md](plans/nvd-vulnerability-adapter.md), status proposed)
* Treat lookup errors differently from "no additional vulnerabilities
  for the affected components", because "no additional vulnerabilities for the affected components"
  means there are now known additional vulnerabilities but a lookup error means, no additional
  vulnerabilities could be retieved, even if there are known vulnerabilities for the component.
  (Today a failed lookup only prints a warning and resolves to no vulnerabilities, see decision
  `:sbom-tool.decision/opt-in-fail-soft-live-lookup`.)
