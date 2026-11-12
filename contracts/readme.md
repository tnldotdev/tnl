# shared inputs

The website consumes these sources from one pinned native revision:

```text
contracts/integrations/telemetry/v1/ --> portable OpenAPI bundle
contracts/fixtures/telemetry/v1/    --> receiver test batch
contracts/regions/v1/catalog.json  --> deployment region metadata
```

The native client owns the telemetry contract. Generation emits Go models and
strict TypeScript validators; the website must consume those validators before
releasing clients with this format. Each batch contains an installation ID and
up to 25 records, each containing `client` metadata and one `event`. Metadata is
captured with the event, so a later sender can batch records from different client
versions without changing their meaning. The receiver must reject the older
batch-level metadata and `publisher.report` formats rather than translate them.

Telemetry describes command outcomes, publication readiness, first demo requests,
integration outcomes, and coarse connection/fallback/recovery measurements. It
does not include traffic volumes, RTT histograms, invocation IDs, or client
timestamps. The receiver enforces 64 KiB batches, 16 KiB records, and unique event
IDs, and deduplicates retries by installation ID and event ID.

The six HTTP serving APIs remain owned by control and publisher; telemetry model
generation adds no native HTTP server. The region catalog is deployment metadata,
not live placement policy or a list of deployed resources.
