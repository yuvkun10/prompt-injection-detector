# Documentation index

- [architecture.md](architecture.md): design constraints, module map, detection pipeline, the `POST /detect` sequence, judge design, and a stage by stage pipeline overview.
- [architecture.mmd](architecture.mmd): Mermaid source of the pipeline overview diagram.
- [diagrams/pipeline.mmd](diagrams/pipeline.mmd): Mermaid source of the full pipeline diagram.
- [threat-model.md](threat-model.md): what the detector catches by category, blind spots, false positive posture, and where the judge helps.
- [usage.md](usage.md): library API and `DetectionResult`, HTTP API, CLI flags and exit codes.
- [configuration.md](configuration.md): `DetectorConfig` fields, thresholds, judge selection and its environment variables.
- [limitations.md](limitations.md): known limits of the heuristic approach.

Design notes in Obsidian format live outside this folder in [`../vault/`](../vault/README.md). Contribution rules are in [`../CONTRIBUTING.md`](../CONTRIBUTING.md).
