
# Architecture Documentation for SBOM Tool
Reads CycloneDX and SPDX software bill of materials files and reports on license and vulnerability compliance.

## Table of Content
1. [Introduction and Goals](#introduction-and-goals)
1. [Architecture Constraints](#architecture-constraints)
1. [System Context and Scope](#system-context-and-scope)
1. [Solution Strategy](#solution-strategy)
1. [Building Block View](#building-blocks)
1. [Runtime View](#runtime-view)
1. [Deployment View](#deployment-view)
1. [Crosscutting Concepts](#crosscutting-concepts)
1. [Architectural Decisions](#architecture-decisions)
1. [Quality Requirements](#quality-requirements)
1. [Risk and Technical Dept](#risk-and-technical-dept)

## Introduction and Goals
<!-- PA-BEGIN(Introduction1) -->
<!-- PA-END(Introduction1) -->


### Goals
| Goal | Description |
|---|---|
| [CI/CD policy gate](../sbom-tool/goal/ci-gate.md) | Let a pipeline fail the build on policy violations via a dedicated exit code, distinct from usage and runtime errors. |
| [VEX-based suppression](../sbom-tool/goal/vex-suppression.md) | Apply suppliers' OpenVEX statements to downgrade or annotate vulnerabilities assessed as not affected or fixed, without changing any other component's report. |
| [canonical SBOM model](../sbom-tool/goal/canonical-sbom-model.md) | Define a single canonical SBOM model so format-specific adapters (CycloneDX, SPDX, ...) can be added without changing reporting logic. |
| [configurable compliance policy](../sbom-tool/goal/configurable-policy.md) | Make license and vulnerability policies (whitelist/blacklist, severity gates, exemptions) configurable via policy files instead of hardcoded. |
| [copyright reporting](../sbom-tool/goal/copyright-reporting.md) | Report resolved copyright notices per component and flag components with missing copyright. |
| [cross-document consolidation](../sbom-tool/goal/consolidate-components.md) | Merge components describing the same package across multiple SBOM documents (matched by purl, falling back to cpe) into one consolidated view. |
| [license reporting](../sbom-tool/goal/license-reporting.md) | Report the set of licenses in the SBOMs, licenses per component, and usage of blacklisted or greylisted licenses. |
| [live vulnerability lookups](../sbom-tool/goal/live-vulnerability-lookup.md) | Optionally enrich SBOM-embedded vulnerability data with live lookups against deps.dev, GitHub Advisory Database or OSV, keyed by component purl. |
| [multi-format SBOM input](../sbom-tool/goal/multi-format-input.md) | Read CycloneDX 1.6 and SPDX 2.2/2.3 SBOM files, with room to add further formats and versions. |
| [multi-format report output](../sbom-tool/goal/multi-format-output.md) | Render any report as EDN, JSON or Markdown, for both tooling and human consumption (e.g. PR summaries). |
| [vulnerability reporting](../sbom-tool/goal/vulnerability-reporting.md) | Report known vulnerabilities per component, from SBOM-embedded data and optional live lookups. |


### Non Goals
| Non-goal | Description |
|---|---|
| [no CVSS Temporal/Environmental scoring](../sbom-tool/goal/no-cvss-temporal-environmental.md) | CVSS vector parsing and scoring covers Base metrics only; Temporal, Environmental and Supplemental metrics are parsed and ignored, never scored. |
| [no cross-run caching](../sbom-tool/goal/no-cross-run-caching.md) | Each invocation is a one-shot, stateless analysis; de-duplication of lookups happens only within a single run, not cached across separate CLI invocations. |
| [no guessed identity merging](../sbom-tool/goal/no-automatic-unidentified-merge.md) | Components carrying neither a purl nor a cpe are never merged across documents by default, since name/version-only matching can wrongly combine unrelated packages; merging them is an explicit opt-in. |
| [no vulnerability research](../sbom-tool/goal/no-vulnerability-discovery.md) | The tool only surfaces vulnerabilities already published in the SBOM or in its configured lookup sources; it performs no vulnerability research of its own. |
| [not a source/binary scanner](../sbom-tool/goal/not-source-scanner.md) | The tool consumes pre-generated SBOM files; it does not analyze source trees, build artifacts or container images to produce an SBOM itself. |
| [not an SBOM generator](../sbom-tool/goal/not-sbom-generator.md) | The tool only reads and reports on existing SBOM files; it does not create, merge or write out a modified SBOM document. |
| [not the sole vulnerability measure](../sbom-tool/goal/not-sole-vulnerability-measure.md) | The SBOM Tool should not be treated as the only measure for vulnerability checks -- it only reports what the SBOMs and optional lookups contain, never a substitute for dedicated scanning. |

<!-- PA-BEGIN(Introduction2) -->
<!-- PA-END(Introduction2) -->

## Architecture Constraints
<!-- PA-BEGIN(ArchitectureConstraints1) -->
<!-- PA-END(ArchitectureConstraints1) -->


### Constraints
| Constraint | Description |
|---|---|
| [Eclipse Public License 1.0](../sbom-tool/constraint/epl-license.md) | The project is licensed under the Eclipse Public License 1.0 (EPL-1.0, see LICENSE); included dependencies must be compatible with it. |
| [mandated input standards](../sbom-tool/constraint/mandated-input-standards.md) | CycloneDX 1.6 and SPDX 2.2 are the mandated baseline SBOM formats/versions the tool must support, independent of which further formats are added. |
| [sbom-tool namespace prefix](../sbom-tool/constraint/namespace-prefix-convention.md) | Every project namespace is prefixed with `sbom-tool`. |

<!-- PA-BEGIN(ArchitectureConstraints2) -->
<!-- PA-END(ArchitectureConstraints2) -->

## System Context and Scope
<!-- PA-BEGIN(SystemContext1) -->
<!-- PA-END(SystemContext1) -->


<!-- PA-BEGIN(SystemContext2) -->
<!-- PA-END(SystemContext2) -->

### Scope
<!-- PA-BEGIN(Scope1) -->
<!-- PA-END(Scope1) -->

<!-- PA-BEGIN(Scope2) -->
<!-- PA-END(Scope2) -->

## Solution Strategy
<!-- PA-BEGIN(SolutionStrategy1) -->
<!-- PA-END(SolutionStrategy1) -->

### Decisions
| Decision | Description |
|---|---|
| [adopt Clean Architecture layering](../sbom-tool/decision/clean-architecture-layering.md) | The codebase is structured as domain/application/adapter layers (src/sbom_tool/domain, application, adapter, see AGENTS.md), keeping SBOM-format and I/O concerns in adapters, independent of the core logic. |
| [implement in Clojure](../sbom-tool/decision/implement-in-clojure.md) | The tool is implemented in Clojure (currently 1.12.5, see project.clj). |
| [normalize SBOM formats into one canonical model](../sbom-tool/decision/canonical-sbom-model.md) | Format-specific adapters (CycloneDX, SPDX) must parse into one canonical SBOM model (AGENTS.md), so reporting and policy logic is written once, independent of the input format. |
| [separate exit codes per failure category](../sbom-tool/decision/separate-exit-codes-per-failure-category.md) | Split the CLI's exit code for usage errors from the one for --fail-on-violations policy violations, which previously both exited 1; usage errors, policy violations and runtime/data errors now each have their own code (0/1/2/3, see dev/plans/cli-error-codes.md), forming a stable contract for CI/CD consumers. |
| [support uberjar and Babashka execution](../sbom-tool/decision/multi-runtime-support.md) | Beyond `lein run`, the tool also runs as a prebuilt uberjar and as a Babashka script (bb.edn), so it can be used without a Leiningen installation (see README.md). |
| [use Leiningen as the build tool](../sbom-tool/decision/leiningen-build.md) | Leiningen (project.clj) manages dependencies, runs tests and produces the uberjar. |

<!-- PA-BEGIN(SolutionStrategy2) -->
<!-- PA-END(SolutionStrategy2) -->

## Building Blocks
<!-- PA-BEGIN(BuildingBlocks1) -->
<!-- PA-END(BuildingBlocks1) -->



<!-- PA-BEGIN(BuildingBlocks2) -->
<!-- PA-END(BuildingBlocks2) -->

## Runtime View
<!-- PA-BEGIN(RuntimeView1) -->
<!-- PA-END(RuntimeView1) -->

<!-- PA-BEGIN(RuntimeView2) -->
<!-- PA-END(RuntimeView2) -->

## Deployment View
<!-- PA-BEGIN(DeploymentView1) -->
<!-- PA-END(DeploymentView1) -->


<!-- PA-BEGIN(DeploymentView2) -->
<!-- PA-END(DeploymentView2) -->

## Crosscutting Concepts
<!-- PA-BEGIN(CrosscuttingConcepts1) -->
<!-- PA-END(CrosscuttingConcepts1) -->

<!-- PA-BEGIN(CrosscuttingConcepts2) -->
<!-- PA-END(CrosscuttingConcepts2) -->


## Architecture Decisions
<!-- PA-BEGIN(ArchitectureDecisions1) -->
<!-- PA-END(ArchitectureDecisions1) -->



<!-- PA-BEGIN(ArchitectureDecisions2) -->
<!-- PA-END(ArchitectureDecisions2) -->

## Quality Requirements
<!-- PA-BEGIN(QualityRequirements1) -->
<!-- PA-END(QualityRequirements1) -->



<!-- PA-BEGIN(QualityRequirements2) -->
<!-- PA-END(QualityRequirements2) -->

## Risk and Technical Dept
### Risks
<!-- PA-BEGIN(Risk1) -->
<!-- PA-END(Risk1) -->



<!-- PA-BEGIN(Risk2) -->
<!-- PA-END(Risk2) -->

### Technical Dept
<!-- PA-BEGIN(TechnicalDept1) -->
<!-- PA-END(TechnicalDept1) -->

<!-- PA-BEGIN(TechnicalDept2) -->
<!-- PA-END(TechnicalDept2) -->


(generated by [Overarch](https://github.com/soulspace-org/overarch) with template docs/arc42.md.cmb)
