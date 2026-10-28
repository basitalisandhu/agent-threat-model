# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.4.0] - 2026-10-29

### Added

- `analyse`, `validate`, `diagram` and `diff` read the system from standard input when the path is `-`, for generated YAML (`generate-system | atm analyse - --fail-on high`). `diff - -` and `validate - -` are refused.
- `atm diff --format csv` writes the change list as CSV (#24).
- README Troubleshooting section built from the real error messages.
- JSON report contract in `docs/report-format.md`, covering the existing version `"1"`, fields, ordering and score meanings, with an example and field tables checked against CLI output (#12).

### Fixed

- A file that is not UTF-8 or YAML nested very deeply no longer crashes with a traceback; every command exits 2 and names the file.
- `-o` pointing at a directory or an unwritable path, and `atm init` into a missing directory, report `error: cannot write ...` and exit 2 instead of crashing.

## [0.3.0] - 2026-10-16

### Added

- `atm analyse --format csv` writes the threat register as CSV, one row per applicable threat in table order, with list columns joined by `;`, for risk registers and spreadsheets (#7). `make reports` also writes `examples/reports/*.csv`.

### Fixed

- MITRE ATLAS references match ATLAS release 2026.09: `AML.T0104` (retired) is now `AML.T0115.002` "Publish Poisoned AI Artifacts: AI Agent Tools", `tool-poisoning` also cites `AML.T0011.002` "User Execution: Poisoned AI Agent Tool", and `AML.T0072` is named "Cyber Communication Channel" (#21).
- OWASP Top 10 for Agentic Applications 2026 titles match the published document: ASI05 "Unexpected Code Execution (RCE)", ASI06 "Memory & Context Poisoning", ASI08 "Cascading Failures" (#21).

### Changed

- uv development dependencies moved to `[dependency-groups]`, which silences a deprecation warning on every `uv run` (#21).

## [0.2.0] - 2026-10-09

### Added

- `atm validate` accepts several files, reports one line per file and exits 2 if any fail; single-file diagnostics retain their parameter hint.
- `atm diagram system.yaml` prints the Mermaid system diagram, or writes it with `-o FILE` (#14, thanks @NurSenaKaraduman).

## [0.1.1] - 2026-10-06

### Changed

- Removed the umbrella branding; this project stands alone and links its sibling repositories directly.

## [0.1.0] - 2026-10-04

### Added

- Container image `ghcr.io/basitalisandhu/agent-threat-model` (entrypoint `atm`) for linux/amd64 and linux/arm64, published on each version tag with an SPDX SBOM, a build provenance attestation and a keyless cosign signature. The image runs as uid 1000 with `/work` as the working directory.
- `atm analyse` with table, Markdown, JSON, SARIF 2.1.0 and HTML output, plus `--fail-on` thresholds.
- `atm validate`, `atm init`, `atm catalogue`, `atm diff` and `atm schema` commands.
- Pydantic v2 input schema with JSON Schema export at `schema/system.schema.json`.
- Catalogue of 30 threats and 29 controls with STRIDE, OWASP Top 10 for LLM Applications 2025, OWASP Top 10 for Agentic Applications 2026 (ids and titles from the OWASP GenAI Security Project crosswalk repository; please check against the published PDF) and MITRE ATLAS mappings.
- Rule DSL (`all`, `any`, `not` over named predicates) evaluated without `eval`.
- Deterministic scoring with inherent and residual severity and a 0..100 residual risk score.
- Mermaid system diagram with untrusted channels drawn in red.
- Four worked examples with committed reports, a composite GitHub Action, CI and release workflows.

### Changed

- Renamed the umbrella project from Hisar to Masoon; links, names and identifiers updated.
- PyPI publishing (release.yml) is off until the repository variable `PYPI_PUBLISH` is set to `true`.

[Unreleased]: https://github.com/basitalisandhu/agent-threat-model/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/basitalisandhu/agent-threat-model/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/basitalisandhu/agent-threat-model/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/basitalisandhu/agent-threat-model/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/basitalisandhu/agent-threat-model/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/basitalisandhu/agent-threat-model/releases/tag/v0.1.0
