# SBOM Tool
Reads software bill of material (SBOM) files and reports on them.
* CycloneDX 1.6 and SPDX 2.2 formats must be supported
  * Other formats/versions could be added
* SBOM Tool implements a canonical SBOM model for SBOMs
  * Adapters handling specific SBOM formats must parse to the canonical SBOM model
* Policies must be configurable (e.g. by specifing a policy config file)
* SBOM Tool reports on licenses and vulnerabilities, e.g.
  * The set of all licenses in the SBOMs
  * The set of licenses per component
  * Usage of blacklisted or greylisted licenses (neither whitelisted, nor blacklisted)
  * Vulnerabilities per component.

# Project Structure
SBOM Tool is a Clojure project using Clean Architecture and is built with Leiningen. The general organization is
* [Source Code](/src/)
* [Test Code](/test)
* [Development Code](/dev)
* [Classpath Resources](/resources)

The all project namespaces are prefixed with `sbom-tool`.
