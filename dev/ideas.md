# Ideas

## SPDX Licenses
* Read SPDX license information as JSON from
  * Github repo -- fetch/refresh the snapshot from spdx/license-list-data at runtime, instead of
    only reading a local file
* Use the SPDX license information in license reports
  * flag deprecated SPDX license ids (`isDeprecatedLicenseId`) distinctly from unidentified ones
  * use the license list as the source of truth for `license/spdx-identifiable?`, instead of the
    current `LicenseRef-` heuristic

## VEX/OpenVEX
* Read VEX information
  * Use VEX information in vulnerability reports

## Vulnerability Database Adapters
* Read current vulnerability information from
  * Google OSV
  * Google deps.dev
  * NVD
  * Github Advisory DB
  * ...
* Use the vulnerability information in reports
  * Enables continous vulnerability checks on SBOMs when the software is already in production
* Use vulnerability information in CI 
  * optional, other tools exist
  