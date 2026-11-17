import { Ajv2020 } from "ajv/dist/2020.js";
import { expect, it } from "vitest";
import { record, repositoryGraph } from "./api-contracts.ts";

it("validates exclusive team/trial ownership without generating union models", async () => {
  const graph = await repositoryGraph();
  // OpenAPI annotations and date formats are not the ownership boundary tested
  // here. the defining schemas still supply every required field and constraint.
  const ajv = new Ajv2020({ strict: false, validateFormats: false });
  for (const owner of ["controlv1", "authorityv1"]) {
    ajv.addSchema(
      { components: graph.bundle(owner).components },
      `https://contracts.test/${owner}.yaml`,
    );
  }
  const service = `svc_${"s".repeat(22)}`;
  const guest = `gst_${"g".repeat(22)}`;
  const now = "2026-11-14T12:00:00Z";
  const serviceFields = {
    id: service,
    name: "demo",
    enabled: true,
    created_at: now,
    protocol: "http",
    publisher_pool: false,
    trust_revision: "1",
  };
  const enrollment = {
    client_id: "publisher",
    key_id: "key",
    grant_id: "grant",
    kind: "service",
    service_id: service,
    expires_at: now,
  };
  const cases: [string, string, Record<string, unknown>, Record<string, unknown>][] = [
    [
      "controlv1",
      "Service",
      {
        ...serviceFields,
        endpoint_revision: "1",
        service_revision: "1",
        ephemeral: true,
        require_post_quantum: false,
      },
      {},
    ],
    ["controlv1", "ServiceSummary", { ...serviceFields, require_post_quantum: false }, {}],
    [
      "controlv1",
      "ServiceRunPreparation",
      {
        service_id: service,
        service_run_id: `srun_${"r".repeat(22)}`,
        run_number: "1",
        run_token: "opaque-run-token",
        publisher_identity_id: "publisher",
        publisher_grant_id: "grant",
        publisher_key_id: "key",
        idempotency_key: "prepare",
        expires_at: now,
        hostname: "demo.example.test",
        domain_id: "domain",
        require_post_quantum: false,
        traffic: {
          connections: 32,
          rate: 20,
          rate_per_ns: 1000000000,
          burst: 40,
          upload_bytes: 8388608,
          download_bytes: 16777216,
        },
      },
      {},
    ],
    [
      "controlv1",
      "Preview",
      { schema_version: 1, id: "preview", service_ids: [service], created_at: now },
      {},
    ],
    [
      "controlv1",
      "Share",
      {
        schema_version: 1,
        id: "share",
        scope: "service",
        label: "",
        service_ids: [service],
        entry_service_id: service,
        created_by_identity_id: "person",
        created_at: now,
        expires_at: now,
      },
      { scope: "guest", created_by_identity_id: undefined },
    ],
    [
      "controlv1",
      "PublisherGrant",
      {
        id: "grant",
        kind: "service",
        service_id: service,
        protocols: ["http"],
        created_at: now,
        expires_at: now,
      },
      {},
    ],
    [
      "controlv1",
      "PublisherIdentity",
      {
        id: "publisher",
        name: "publisher",
        kind: "installed",
        ownership: "team",
        created_at: now,
        grants: [],
      },
      { kind: "guest", ownership: "guest" },
    ],
    ["controlv1", "PublisherEnrollmentResult", enrollment, {}],
    ["authorityv1", "PublisherEnrollmentResult", enrollment, {}],
  ];
  for (const [owner, name, fields, guestChanges] of cases) {
    const schema = record(record(record(graph.bundle(owner).components).schemas)[name]);
    for (const union of ["oneOf", "anyOf", "allOf"])
      expect(schema[union], `${name}.${union}`).toBeUndefined();
    const validate = ajv.compile({
      $ref: `https://contracts.test/${owner}.yaml#/components/schemas/${name}`,
    });
    const teamValue = { ...fields, team_id: "team" };
    const guestValue = { ...fields, ...guestChanges, guest_id: guest };
    expect(validate(teamValue), `${owner}.${name}: ${JSON.stringify(validate.errors)}`).toBe(true);
    expect(validate(guestValue), `${owner}.${name}: ${JSON.stringify(validate.errors)}`).toBe(true);
    for (const invalid of [
      fields,
      { ...guestValue, team_id: "team" },
      { ...teamValue, guest_id: "" },
      { ...guestValue, team_id: "" },
      { ...fields, team_id: "" },
      { ...fields, guest_id: "" },
    ])
      expect(validate(invalid), `${owner}.${name}: ${JSON.stringify(invalid)}`).toBe(false);
    if (name === "PublisherEnrollmentResult" || name === "PublisherGrant") {
      for (const forbidden of ["public_url_id", "namespace", "domain_id"]) {
        expect(validate({ ...guestValue, [forbidden]: "other" }), `${name}.${forbidden}`).toBe(
          false,
        );
      }
      expect(validate({ ...guestValue, kind: "namespace" })).toBe(false);
      for (const missing of ["service_id", "expires_at"]) {
        const value: Record<string, unknown> = { ...guestValue };
        delete value[missing];
        expect(validate(value), `${name} missing ${missing}`).toBe(false);
      }
    }
  }
});
