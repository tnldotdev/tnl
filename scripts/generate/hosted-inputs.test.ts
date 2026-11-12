import { Ajv2020 } from "ajv/dist/2020.js";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { expect, it } from "vitest";
import { z } from "zod";
import { operationInventory, record, repositoryGraph, root } from "./api-contracts.ts";

it("bundles the hosted telemetry receiver with its bounded, closed event schemas", async () => {
  const document = (await repositoryGraph()).bundle("telemetryv1");
  expect(operationInventory(document)).toEqual([
    { method: "post", path: "/api/telemetry", operationId: "recordTelemetryBatch" },
  ]);
  const ajv = new Ajv2020({ strictTypes: false });
  // these are annotations, not validation rules. unknown validation keywords still fail.
  for (const keyword of ["components", "discriminator", "x-go-type-skip-optional-pointer"])
    ajv.addKeyword(keyword);
  ajv.addFormat("int64", { type: "number", validate: Number.isSafeInteger });
  const validate = ajv.compile({
    components: document.components,
    $ref: "#/components/schemas/Batch",
  });
  const batch = record(
    JSON.parse(await readFile(join(root, "contracts/fixtures/telemetry/v1/batch.json"), "utf8")),
  );
  expect(validate(batch), JSON.stringify(validate.errors)).toBe(true);
  const events = z.array(z.record(z.string(), z.unknown())).parse(batch.events);
  expect(events).toHaveLength(5);
  const event = record(events[0]?.event);
  for (const change of [
    { raw_url: "https://private.invalid" },
    { schema_version: 2 },
    { installation_id: "not-an-installation-id" },
    { events: [] },
    { events: Array.from({ length: 26 }, () => events[0]) },
    { client: record(events[0]?.client) },
    { events: [event] },
    { events: [{ ...events[0], event: { ...event, name: "unknown.event" } }] },
    { events: [{ ...events[0], event: { ...event, name: "publisher.report" } }] },
    { events: [{ ...events[0], raw_url: "https://private.invalid" }] },
    {
      events: [
        {
          ...events[0],
          event: { ...event, payload: { ...record(event.payload), raw_command: "secret" } },
        },
      ],
    },
    {
      events: [
        { ...events[0], client: { ...record(events[0]?.client), hostname: "private.invalid" } },
      ],
    },
  ])
    expect(validate({ ...batch, ...change }), JSON.stringify(change)).toBe(false);
});

it("keeps the shared region catalog versioned, bounded, and unambiguous", async () => {
  const catalog = z
    .strictObject({
      schema_version: z.literal(1),
      locations: z
        .array(
          z.strictObject({
            code: z.string().regex(/^[a-z]{3}$/),
            name: z.string().min(1),
            country: z.string().regex(/^[A-Z]{2}$/),
            latitude: z.number().min(-90).max(90),
            longitude: z.number().min(-180).max(180),
            providers: z.partialRecord(
              z.enum([
                "aws",
                "azure",
                "digitalocean",
                "fly",
                "gcp",
                "hetzner",
                "linode",
                "oci",
                "scaleway",
                "vultr",
              ]),
              z.array(z.string().min(1)).min(1),
            ),
          }),
        )
        .min(2),
    })
    .parse(JSON.parse(await readFile(join(root, "contracts/regions/v1/catalog.json"), "utf8")));
  const codes = catalog.locations.map(({ code }) => code);
  expect(new Set(codes).size).toBe(codes.length);
  const identifiers = catalog.locations.flatMap(({ providers }) =>
    Object.entries(providers).flatMap(([provider, regions]) =>
      (regions ?? []).map((region) => `${provider}:${region}`),
    ),
  );
  expect(new Set(identifiers).size).toBe(identifiers.length);
  for (const code of ["sjc", "gru"])
    expect(catalog.locations.find((location) => location.code === code)?.providers.fly).toContain(
      code,
    );
});
