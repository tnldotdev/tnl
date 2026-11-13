import assert from "node:assert/strict";
import { stdin, stdout } from "node:process";
import * as z from "zod";
import { createClient, deployments, publishers } from "@tnldotdev/tnl/http";

const parts: Buffer[] = [];
for await (const chunk of stdin) parts.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
const input = z
  .strictObject({
    server: z.url(),
    team_id: z.string(),
    project_key: z.string(),
    token: z.string(),
    phase: z.enum(["create", "publishers", "revoked"]),
    deployment_id: z.string().optional(),
    publisher_id: z.string().optional(),
  })
  .parse(JSON.parse(Buffer.concat(parts).toString("utf8")));
const client = createClient({ baseUrl: input.server, auth: input.token });
const query = { team_id: input.team_id };
const project = { project_key: input.project_key };
const options = { client, query, throwOnError: true as const };
const original = {
  name: "customer",
  targets: { db: { address: "customer.internal:5432", tls: { ca: "system" } } },
};
const creation = {
  ...options,
  path: project,
  headers: { "Idempotency-Key": "original-customer" },
  body: original,
};
const result: Record<string, string> = {};

if (input.phase === "create") {
  const production = await deployments.get({
    ...options,
    path: { ...project, deployment: "production" },
  });
  assert.deepEqual(
    Object.keys(production.data.services),
    ["db"],
    "management read widened its service allowlist",
  );
  assert.deepEqual(
    Object.keys(production.data.targets),
    ["db"],
    "management read exposed unapproved targets",
  );
  const forbidden = await deployments.create({
    ...creation,
    headers: { "Idempotency-Key": "unapproved-web" },
    body: { name: "forbidden", targets: { web: { address: "web:3000" } } },
    throwOnError: false,
  });
  assert.equal(forbidden.response?.status, 403);
  const foreign = await deployments.list({
    ...options,
    path: project,
    query: { team_id: "tm_other" },
    throwOnError: false,
  });
  assert.equal(foreign.response?.status, 403);
  const created = await deployments.create(creation);
  const path = { ...project, deployment: created.data.id };
  const firstETag = created.response.headers.get("etag");
  assert(firstETag && /^"[0-9]+"$/.test(firstETag), "creation lost its strong ETag");
  const missing = await deployments.update({
    ...options,
    path,
    body: { targets: { db: { address: "changed:5432" } } },
    throwOnError: false,
  });
  assert.equal(missing.response?.status, 428);
  const updated = await deployments.update({
    ...options,
    path,
    headers: { "If-Match": firstETag },
    body: { targets: { db: { address: "changed.internal:5432", tls: { ca: "system" } } } },
  });
  assert.notEqual(updated.response.headers.get("etag"), firstETag);
  const stale = await deployments.update({
    ...options,
    path,
    headers: { "If-Match": firstETag },
    body: { targets: { db: { address: "stale:5432" } } },
    throwOnError: false,
  });
  assert.equal(stale.response?.status, 412);
  const recovered = await deployments.create(creation);
  assert.equal(recovered.data.id, created.data.id);
  assert.equal(recovered.data.revision, updated.data.revision);
  assert.equal(recovered.data.targets.db?.address, "changed.internal:5432");
  const changed = await deployments.create({
    ...creation,
    body: { ...original, name: "different" },
    throwOnError: false,
  });
  assert.equal(changed.response?.status, 409);
  const page = await deployments.list({ ...options, path: project, query: { ...query, limit: 1 } });
  assert.equal(page.data.deployments.length, 1);
  assert(page.data.next_cursor, "filtered pagination lost its cursor");
  const next = await deployments.list({
    ...options,
    path: project,
    query: { ...query, limit: 1, after: page.data.next_cursor },
  });
  assert.equal(next.data.deployments.length, 1);
  assert.notEqual(next.data.deployments[0]?.id, page.data.deployments[0]?.id);
  const setup = {
    ...options,
    path,
    headers: { "Idempotency-Key": "original-setup" },
    body: { services: ["db"], max_members: 1, expires_in: 600 },
  };
  const enrollment = await publishers.createEnrollment(setup);
  const retry = await publishers.createEnrollment(setup);
  assert(
    enrollment.data.enrollment_key === retry.data.enrollment_key,
    "setup retry replaced its original key",
  );
  assert.equal(enrollment.data.expires_at, retry.data.expires_at);
  assert.deepEqual(enrollment.data.services, { db: "postgres" });
  result.deployment_id = created.data.id;
  result.enrollment_key = enrollment.data.enrollment_key;
} else if (input.phase === "publishers") {
  assert(input.deployment_id && input.publisher_id);
  const path = { ...project, deployment: input.deployment_id };
  const publisherPath = { ...path, publisher: input.publisher_id };
  const listed = await publishers.list({ ...options, path });
  assert.equal(listed.data.publishers.length, 1);
  const read = await publishers.get({ ...options, path: publisherPath });
  assert.equal(read.data.publisher_identity_id, input.publisher_id);
  assert.deepEqual(read.data.services, { db: "postgres" });
  assert.equal(read.data.healthy, false, "enrollment was mistaken for traffic readiness");
  await publishers.revoke({ ...options, path: publisherPath });
  await publishers.revoke({ ...options, path: publisherPath });
  const revoked = await publishers.get({ ...options, path: publisherPath });
  assert(revoked.data.revoked_at, "revocation lost its retained observation");
  const deployment = await deployments.get({ ...options, path });
  const condition = deployment.response.headers.get("etag");
  assert(condition);
  await deployments.delete({ ...options, path, headers: { "If-Match": condition } });
  const readDeleted = await deployments.get({ ...options, path, throwOnError: false });
  assert.equal(readDeleted.response?.status, 404);
  const replay = await deployments.create({ ...creation, throwOnError: false });
  assert.equal(replay.response?.status, 409);
  const sibling = await deployments.get({
    ...options,
    path: { ...project, deployment: "production" },
  });
  assert.equal(sibling.data.targets.db?.address, "db.internal:5432");
} else {
  const denied = await deployments.list({ ...options, path: project, throwOnError: false });
  assert.equal(denied.response?.status, 401, "management ignored current grant revocation");
}
stdout.write(JSON.stringify(result));
