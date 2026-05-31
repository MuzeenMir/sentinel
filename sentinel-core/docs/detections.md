# Detection-as-Code

SENTINEL detection logic is stored as reviewed code under
`sentinel-core/detections/`. The tree contains Sigma YAML rules, custom Python
detectors, and `detections.config.yaml`, which is the configuration surface for
enabled detection sets and severity overrides.

## Sigma Rules

Author Sigma rules in `sentinel-core/detections/sigma/`. Each rule must include:

- `id`
- `title`
- `logsource`
- `detection`
- `level`

IDs are stable API. Use the `sentinel.sigma.*` namespace and never reuse an id
for a different analytic. The registry currently validates supported
logsources for Linux authentication, Linux and Windows process creation,
network connections, CloudTrail, and application webserver events.

## Python Detectors

Custom Python detectors live in `sentinel-core/detections/python/`. Each module
exports a `DETECTORS` list. Each detector object must expose:

```python
id = "sentinel.python.example"

def evaluate(self, event: dict) -> Finding | None:
    ...
```

Return `detection_engine.Finding` when an event matches, and `None` when it does
not. Detectors must be deterministic and free of network or database side
effects during import and evaluation.

## Validation

Run the validator before opening a PR:

```bash
python sentinel-core/scripts/validate_detections.py
```

The validator checks Sigma schema, unique ids, supported logsources, Python
detector imports, and detector protocol conformance. The same checks run in
the `detections-validate` GitHub Actions workflow whenever detection files,
the registry, or validator tests change.

## GitOps Flow

Detection changes are normal pull requests:

1. Add or update Sigma/Python detection content.
2. Run `validate_detections.py` and detector tests locally.
3. Open a PR and wait for `detections-validate`.
4. Merge only after normal code review and green CI.

This keeps detection behavior reviewable, reproducible, and deployable from
Git without silent embedded logic.

## OPA Deferral

OPA policy bundles are intentionally out of scope for this wedge. They touch
policy and governance boundaries that require the separate two-person review
path. This detection-as-code flow covers Sigma and Python detectors only.
