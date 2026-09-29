# Ideas

## CLI Error Codes
* An error code of `1` should flag policy violations only, not CLI usage errors or other errors.
* CLI usage errors should be flagged by either error code `2` or a new error code `3` to separate
  them from program errors.

## SPDX Licenses
* Read SPDX license information as JSON from
  * Github repo -- fetch/refresh the snapshot from spdx/license-list-data at runtime, instead of
    only reading a local file
* Use the SPDX license information in license reports
  * flag deprecated SPDX license ids (`isDeprecatedLicenseId`) distinctly from unidentified ones
  * use the license list as the source of truth for `license/spdx-identifiable?`, instead of the
    current `LicenseRef-` heuristic

## Vulnerability Database Adapters
* Read current vulnerability information from
  * NVD
  * ...
* Treat lookup errors differently from "no additional vulnerabilities
  for the affected components", because "no additional vulnerabilities for the affected components"
  means there are now known additional vulnerabilities but a lookup error means, no additional
  vulnerabilities could be retieved, even if there are known vulnerabilities for the component.
  