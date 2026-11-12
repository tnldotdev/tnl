# shared inputs

The website consumes these sources from one pinned native revision:

```text
contracts/integrations/telemetry/v1/ --> portable OpenAPI bundle
contracts/fixtures/telemetry/v1/    --> receiver test batch
contracts/regions/v1/catalog.json  --> deployment region metadata
```

The telemetry contract describes the existing website receiver. Portable export
includes it, but native Go HTTP generation still covers only the six APIs served
by control and publisher. This does not migrate the CLI's older telemetry payloads,
enable native OTLP export, or change any telemetry preference.

These inputs restore the definitions authored in `fb50c6823` (telemetry) and
`5ed238eca` (regions), which the website already consumes. The region catalog is
metadata, not live placement policy or a list of deployed resources.
