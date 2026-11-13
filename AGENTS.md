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
* [Source Code](src)
* [Test Code](test)
* [Development Code](dev)
* [Classpath Resources](resources)
* [Overarch Model](models)
* [Overarch Templates](templates)
* [Tools](tools)

The all project namespaces are prefixed with `sbom-tool`.

# Overarch Model
Use the `architecture-modelling` skill for model editing and the `architecture-query` skill to answer questions about the architecture of the SBOM Tool (don't rely on the generated documentation in `docs`, it may not be current).

# Agent Skills: Project Specifics
The agent skills in [.claude/skills](.claude/skills) are project-independent. Their shared rules are in [.claude/references/principles.md](.claude/references/principles.md), [.claude/references/model-change-policy.md](.claude/references/model-change-policy.md) and [.claude/references/decision-records.md](.claude/references/decision-records.md). Everything specific to this project is defined here.

## Model Tooling and References
* Overarch is `tools/overarch.jar`, run with `java -jar` from the repository root, model directory `models`, id namespace prefix `sbom-tool`.
* The references for the `architecture-modelling` and `architecture-query` skills are [.claude/references/modelling-reference.md](.claude/references/modelling-reference.md) (file format, ids, hierarchy, relations, views, validation) and [.claude/references/model-query-reference.md](.claude/references/model-query-reference.md) (element types and keys by model area).
* Model changes follow [.claude/references/model-change-policy.md](.claude/references/model-change-policy.md); decisions follow [.claude/references/decision-records.md](.claude/references/decision-records.md).

## Build, Test and Validation
* Run tests with `bb test` (Babashka). Leiningen may not be installed; `lein` is the official build tool (see `project.clj`).
* Validate the model with `java -jar tools/overarch.jar -m models -S '{:namespace-prefix "sbom-tool"}'`.
* Don't run `model.sh` (generation) unless asked, it rewrites the derived documentation.

## Architecture Rules
* Clean Architecture layers in `src/sbom_tool`: `domain`, `application`, `adapter`. Dependencies point inward. Adapters parse SBOM formats into the canonical SBOM model; the core knows neither formats nor I/O.
* Adapter namespaces may depend on each other as long as no cycles are introduced.
* `src/sbom_tool/util` holds general helpers. Its namespaces (e.g. `sbom-tool.util.functions`) are leaves: they depend on no other project namespace and may be used from any layer.
* Model ids use the namespace prefix `sbom-tool` (e.g. `:sbom-tool.decision/...`, `:sbom-tool.goal/...`).
* Public contracts (changes are Tier 3 in the model change policy): CLI options and exit codes, the policy file formats, the report output formats, the supported SBOM formats and versions.

## Where Things Live
* Model files in `models/sbom-tool`: `architecture.edn`, `code.edn`, `goals.edn`, `use-cases.edn`, `constraints.edn`, `decisions.edn`, `views.edn`.
* Decisions are `:decision` elements in `decisions.edn`, tagged `"solution strategy"`, linked with `:implements` to goals and constraints.
* Risks and technical debts are `:risk` elements in `risks.edn`, technical debts are tagged `"technical debt"`, linked with `:risk-for` to the affected elements.
* Plans for larger features are in `dev/plans/*.md`, ideas in `dev/ideas.md`, assessments in `dev/assessments`. Check for an existing plan before starting and keep its status current.
* Plan format: title `# Plan: <name>`, header lines `**Status:**`, `**Date:**` (ISO), `**Related:**`, then sections Goals, Non-goals, Problem, Design, Step-by-step implementation, File-by-file summary, Verification, Risks / open questions, Follow-ups. Existing plans are the template.
* Plan status values in use: `proposed` and `implemented`. No other values are defined; propose any further ones (e.g. for approved or in-progress) to the maintainer instead of inventing them. Only the maintainer moves a plan beyond `proposed`.
* Tests are `test/**/*_test.clj`, mirroring the source namespaces. The model has no test elements: the `test-agent` works from the use cases in `use-cases.edn`, the Verification sections of plans and the test sources.
* The model has no requirement, capability, process, concept, deployment or test elements (yet). The product, domain, operations and test agents work from goals, use cases, plans, code and tests, and may propose modelling these areas (Tier 1).

## Security Starting Points
* Untrusted inputs: SBOM files (CycloneDX, SPDX), policy config files, CLI arguments.
* External services used by the vulnerability adapters (OSV, NVD, GitHub advisories, deps.dev): transport, API keys, response trust, rate limits and failure behavior.
* The tool's own dependencies in `project.clj` and their licenses.
* Output that could leak data: reports, logs, error messages.
