import { Ajv2020 } from "ajv/dist/2020.js";
import { expect, it } from "vitest";
import { record, repositoryGraph } from "./api-contracts.ts";

it("requires bounded protocols on actual exact grants and pending enrollments only", async () => {
  const graph = await repositoryGraph();
  const ajv = new Ajv2020({ strict: false, validateFormats: false });
  ajv.addSchema(
    { components: graph.bundle("controlv1").components },
    "https://contracts.test/control",
  );
  const validate = (name: string) =>
    ajv.compile({ $ref: `https://contracts.test/control#/components/schemas/${name}` });
  const service = `svc_${"s".repeat(22)}`;
  for (const name of ["PublisherGrant", "PublisherEnrollment"]) {
    const check = validate(name);
    const value = {
      id: "grant",
      team_id: "team",
      kind: "service",
      service_id: service,
      ...(name === "PublisherGrant"
        ? { created_at: "2026-11-15T12:00:00Z" }
        : { enrollment_key: "secret", expires_at: "2026-11-15T12:00:00Z" }),
    };
    expect(check({ ...value, protocols: ["http", "postgres"] }), name).toBe(true);
    expect(check(value), `${name} missing capability`).toBe(false);
    for (const protocols of [null, [], ["http", "http"], ["ssh"], ["*"], "http"]) {
      expect(check({ ...value, protocols }), `${name} ${JSON.stringify(protocols)}`).toBe(false);
    }
    const namespace = { ...value, kind: "namespace", service_id: undefined };
    expect(check(namespace), `${name} namespace`).toBe(true);
    expect(check({ ...namespace, protocols: ["http"] }), `${name} namespace capability`).toBe(
      false,
    );
  }
  for (const name of ["CreatePublisherEnrollmentRequest", "CreatePublisherGrantRequest"]) {
    const check = validate(name);
    const value = {
      team_id: "team",
      service_id: service,
      ...(name === "CreatePublisherEnrollmentRequest"
        ? { name: "publisher", kind: "installed" }
        : {}),
    };
    expect(check(value), `${name} issuer default`).toBe(true);
    expect(check({ ...value, protocols: ["postgres"] }), `${name} explicit`).toBe(true);
    expect(
      check({ ...value, protocols: ["http"], service_id: undefined }),
      `${name} namespace`,
    ).toBe(false);
    for (const protocols of [null, [], ["http", "http"], ["ssh"]])
      expect(check({ ...value, protocols }), name).toBe(false);
  }
  for (const owner of ["controlv1", "authorityv1"]) {
    const schema = record(
      record(record(graph.bundle(owner).components).schemas).PublisherEnrollmentResult,
    );
    expect(record(schema.properties).protocols, `${owner} portable credential`).toBeUndefined();
  }
});

it("keeps reserve request-only on canonical service creation with recovery status", async () => {
  const bundle = (await repositoryGraph()).bundle("controlv1");
  const ajv = new Ajv2020({ strict: false, validateFormats: false });
  ajv.addSchema({ components: bundle.components }, "https://contracts.test/control");
  const check = ajv.compile({
    $ref: "https://contracts.test/control#/components/schemas/CreateServiceRequest",
  });
  for (const reserve of [undefined, false, true])
    expect(check({ team_id: "team", name: "preview", reserve })).toBe(true);
  for (const reserve of [null, "true", 1, {}])
    expect(check({ team_id: "team", name: "preview", reserve })).toBe(false);
  const schemas = record(record(bundle.components).schemas);
  expect(record(record(schemas.Service).properties).reserve).toBeUndefined();
  const responses = record(record(record(record(bundle.paths)["/v1/services"]).post).responses);
  expect(responses["200"]).toBeDefined();
  expect(responses["201"]).toBeDefined();
});
