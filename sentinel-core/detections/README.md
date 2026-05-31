# Detection Authoring

Detections live in this tree so review, CI, and deployment can treat them as
code.

## Sigma Rules

Place Sigma YAML rules in `sigma/`. Each rule must include:

- `id`
- `title`
- `logsource`
- `detection`
- `level`

IDs must be globally unique. Use stable IDs under the `sentinel.sigma.*`
namespace.

## Python Detectors

Place custom detectors in `python/`. Each module exports `DETECTORS`, a list of
objects with an `id` string and `evaluate(event)` method. `evaluate()` returns a
`detection_engine.Finding` for suspicious events and `None` otherwise.

Run validation before opening a PR:

```bash
python sentinel-core/scripts/validate_detections.py
```
