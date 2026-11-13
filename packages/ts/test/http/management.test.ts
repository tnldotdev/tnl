import { execFile } from "node:child_process";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { describe, expect, it, vi } from "vitest";
import * as http from "@tnldotdev/tnl/http";
import { createClient, deployments, publishers, type Deployment } from "@tnldotdev/tnl/http";

const project = { project_key: "shop" };
const query = { team_id: "team-shop" };
const serviceId = `svc_${"a".repeat(22)}`;
const deployment: Deployment = {
  id: "pgrp_customer",
  team_id: query.team_id,
  project_key: project.project_key,
  name: "customer",
  revision: 1,
  targets: { db: { address: "db.internal:5432", tls: { ca: "system" } } },
  services: { db: { id: serviceId, protocol: "postgres", trust_revision: 1 } },
};
const member = {
  team_id: query.team_id,
  project_key: project.project_key,
  group_id: deployment.id,
  group_name: deployment.name,
  publisher_identity_id: "pub_customer",
  key_id: "key_customer",
  observed_revision: 1,
  current_revision: 1,
  snapshot_at: "2026-11-13T12:00:00+01:00",
  healthy: false,
  services: { db: "postgres" },
};
const path = { ...project, deployment: deployment.id };
const json = (value: unknown, status = 200) =>
  Response.json(value, { status, headers: { ETag: '"1"' } });

function fetchRequest(input: Parameters<typeof fetch>[0]): Request {
  expect(input).toBeInstanceOf(Request);
  if (!(input instanceof Request)) throw new Error("expected a stock Fetch request");
  return input;
}

type FetchCall = (...args: Parameters<typeof fetch>) => ReturnType<typeof fetch>;
function mockTransport(implementation: FetchCall) {
  // bun augments fetch with preconnect; keep the same test transport assignable.
  return Object.assign(vi.fn(implementation), { preconnect() {} });
}

describe("HTTP management entry point", () => {
  it("exports only transport configuration and the nine approved operations", () => {
    expect(Object.keys(http).sort()).toEqual([
      "createClient",
      "createConfig",
      "deployments",
      "publishers",
    ]);
    const methods = (container: object) =>
      Object.getOwnPropertyNames(container)
        .filter((name) => !["length", "name", "prototype"].includes(name))
        .sort();
    expect(methods(deployments)).toEqual(["create", "delete", "get", "list", "update"]);
    expect(methods(publishers)).toEqual(["createEnrollment", "get", "list", "revoke"]);
  });

  it("imports without any Node built-ins or native process dependencies", async () => {
    const loader = fileURLToPath(new URL("../fixtures/http-only-loader.ts", import.meta.url));
    const { stdout } = await promisify(execFile)(
      process.execPath,
      [
        "--loader",
        loader,
        "--input-type=module",
        "-e",
        'const api = await import("@tnldotdev/tnl/http"); console.log(Object.keys(api).sort().join(","));',
      ],
      { cwd: fileURLToPath(new URL("../../", import.meta.url)) },
    );
    expect(stdout.trim()).toBe("createClient,createConfig,deployments,publishers");
  });

  it("sends canonical operations, original creation keys, conditions, and bearer auth", async () => {
    const requests: Request[] = [];
    const transport = mockTransport(async (input) => {
      const request = fetchRequest(input);
      requests.push(request);
      const url = new URL(request.url);
      expect(url.searchParams.get("team_id")).toBe(query.team_id);
      expect(request.headers.get("authorization")).toBe("Bearer scoped-token");
      if (url.pathname.endsWith("/publisher-enrollments"))
        return json(
          {
            enrollment_key: "private-enrollment",
            enrollment_id: "pge_customer",
            group_id: deployment.id,
            expires_at: "2026-11-13T13:00:00Z",
            max_members: 1,
            services: { db: "postgres" },
          },
          201,
        );
      if (url.pathname.endsWith("/publishers"))
        return json({ publishers: [member], next_cursor: "publisher-next" });
      if (url.pathname.endsWith("/pub_customer"))
        return request.method === "DELETE" ? new Response(null, { status: 204 }) : json(member);
      if (request.method === "DELETE") return new Response(null, { status: 204 });
      if (url.pathname.endsWith("/deployments") && request.method === "GET")
        return json({ deployments: [deployment], next_cursor: "deployment-next" });
      return json(deployment, request.method === "POST" ? 201 : 200);
    });
    const client = createClient({
      baseUrl: "https://control.example.test",
      auth: "scoped-token",
      fetch: transport,
    });
    const options = { client, query, throwOnError: true as const };
    const created = await deployments.create({
      ...options,
      path: project,
      headers: { "Idempotency-Key": "original-create" },
      body: { name: "customer", targets: { db: { address: "db.internal:5432" } } },
    });
    expect(created.data).toEqual(deployment);
    expect(created.response.headers.get("etag")).toBe('"1"');
    expect(
      (
        await deployments.list({
          ...options,
          path: project,
          query: { ...query, after: "previous", limit: 1 },
          headers: new Headers({ "X-Caller": "fetch-headers" }),
        })
      ).data.next_cursor,
    ).toBe("deployment-next");
    await deployments.get({ ...options, path });
    await deployments.update({
      ...options,
      path,
      headers: { "If-Match": '"1"' },
      body: {
        targets: {
          db: {
            address: "replacement.internal:5432",
            tls: { ca: "system", hostname: "db.internal" },
          },
        },
      },
    });
    const enrollment = await publishers.createEnrollment({
      ...options,
      path,
      headers: { "Idempotency-Key": "original-enrollment" },
      body: { services: ["db"], max_members: 1, expires_in: 600 },
    });
    expect(enrollment.data.enrollment_key).toBe("private-enrollment");
    expect((await publishers.list({ ...options, path })).data.next_cursor).toBe("publisher-next");
    const publisherPath = { ...path, publisher: "pub_customer" };
    expect((await publishers.get({ ...options, path: publisherPath })).data.services).toEqual({
      db: "postgres",
    });
    expect((await publishers.revoke({ ...options, path: publisherPath })).response.status).toBe(
      204,
    );
    expect(
      (await deployments.delete({ ...options, path, headers: { "If-Match": '"1"' } })).response
        .status,
    ).toBe(204);
    expect(requests).toHaveLength(9);
    expect(requests.map(({ method }) => method)).toEqual([
      "POST",
      "GET",
      "GET",
      "PATCH",
      "POST",
      "GET",
      "GET",
      "DELETE",
      "DELETE",
    ]);
    expect(requests[0]?.headers.get("idempotency-key")).toBe("original-create");
    expect(requests[4]?.headers.get("idempotency-key")).toBe("original-enrollment");
    expect(requests[3]?.headers.get("if-match")).toBe('"1"');
    expect(requests[8]?.headers.get("if-match")).toBe('"1"');
    expect(await requests[3]?.json()).toEqual({
      targets: {
        db: {
          address: "replacement.internal:5432",
          tls: { ca: "system", hostname: "db.internal" },
        },
      },
    });
    expect(new URL(requests[1]?.url ?? "").searchParams.get("after")).toBe("previous");
    expect(requests[1]?.headers.get("x-caller")).toBe("fetch-headers");
  });

  it.each([412, 428, 403, 404])(
    "retains HTTP %i problems and response headers without replay",
    async (status) => {
      const problem = {
        type: "about:blank",
        title: "request rejected",
        status,
        code: "conflict",
        detail: "read current state",
        request_id: "request-test",
      };
      const transport = mockTransport(async () => json(problem, status));
      const client = createClient({ baseUrl: "https://control.example.test", fetch: transport });
      const result = await deployments.update({
        client,
        path,
        query,
        body: { targets: { db: { address: "changed:5432" } } },
        throwOnError: false,
      });
      expect(result.error).toEqual(problem);
      expect(result.response?.status).toBe(status);
      expect(result.response?.headers.get("etag")).toBe('"1"');
      expect(transport).toHaveBeenCalledTimes(1);
    },
  );

  it.each([
    { ...deployment, unexpected: "private" },
    { ...deployment, revision: "1" },
    { ...deployment, services: { db: { id: serviceId, protocol: "ssh", trust_revision: 1 } } },
  ])("rejects malformed successful responses", async (invalid) => {
    const client = createClient({
      baseUrl: "https://control.example.test",
      fetch: mockTransport(async () => json(invalid)),
    });
    await expect(
      deployments.get({ client, path, query, throwOnError: true }),
    ).rejects.toMatchObject({ name: "ZodError" });
  });

  it("keeps independently configured clients isolated during concurrent calls", async () => {
    const seen: string[] = [];
    const transport = mockTransport(async (input) => {
      const request = fetchRequest(input);
      seen.push(`${new URL(request.url).host}:${request.headers.get("authorization")}`);
      return json(deployment);
    });
    const first = createClient({
      baseUrl: "https://first.example.test",
      auth: "first",
      fetch: transport,
    });
    const second = createClient({
      baseUrl: "https://second.example.test",
      auth: "second",
      fetch: transport,
    });
    await Promise.all(
      [first, second, first, second].map((client) =>
        deployments.get({ client, path, query, throwOnError: true }),
      ),
    );
    expect(seen).toEqual([
      "first.example.test:Bearer first",
      "second.example.test:Bearer second",
      "first.example.test:Bearer first",
      "second.example.test:Bearer second",
    ]);
  });

  it("preserves abort signals and network failures without retries", async () => {
    const reason = new Error("request canceled");
    const signal = AbortSignal.abort(reason);
    const transport = mockTransport(async (input) => {
      const request = fetchRequest(input);
      expect(request.signal.aborted).toBe(true);
      throw reason;
    });
    const client = createClient({ baseUrl: "https://control.example.test", fetch: transport });
    await expect(deployments.get({ client, path, query, signal, throwOnError: true })).rejects.toBe(
      reason,
    );
    expect(transport).toHaveBeenCalledTimes(1);
  });
});
