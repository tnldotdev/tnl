import { createHash } from "node:crypto";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  ContractGraph,
  contracts,
  operationInventory,
  record,
  repositoryGraph,
  root,
} from "./openapi.ts";

const directories: string[] = [];
afterEach(async () => {
  await Promise.all(
    directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })),
  );
});

async function fixture<Key extends string>(
  files: Record<Key, unknown>,
): Promise<Record<Key, string>> {
  const directory = await mkdtemp(join(tmpdir(), "tnl-openapi-test-"));
  directories.push(directory);
  const entries: Record<string, string> = {};
  for (const [file, document] of Object.entries(files)) {
    const path = join(directory, file);
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, typeof document === "string" ? document : JSON.stringify(document));
    entries[file] = path;
  }
  // every supplied key was written above; preserve that finite key set for callers.
  return entries as Record<Key, string>;
}

function document(paths: unknown = {}, schemas: unknown = {}): Record<string, unknown> {
  return {
    openapi: "3.1.0",
    info: { title: "fixture", version: "1" },
    paths,
    components: { schemas },
  };
}

function canonical(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonical);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(record(value))
        .sort(([a], [b]) => a.localeCompare(b, "en"))
        .map(([key, item]) => [key, canonical(item)]),
    );
  }
  return value;
}

function hash(value: unknown): string {
  return createHash("sha256")
    .update(JSON.stringify(canonical(value)))
    .digest("hex");
}

describe("OpenAPI graph", () => {
  it("resolves escaped pointers, nested fragments, sibling fields, and named recursive schemas deterministically", async () => {
    const files = await fixture({
      "openapi.yaml": document(
        { "/v1/items": { $ref: "paths/items.yaml#/paths/~1v1~1items" } },
        { Item: { $ref: "schemas/items.yaml#/Item" } },
      ),
      "paths/items.yaml": {
        paths: { "/v1/items": { $ref: "nested.yaml#/item", description: "path description" } },
      },
      "paths/nested.yaml": {
        item: {
          get: {
            operationId: "getItems",
            responses: {
              "200": {
                description: "ok",
                content: {
                  "application/json": { schema: { $ref: "../schemas/items.yaml#/Item" } },
                },
              },
            },
          },
        },
      },
      "schemas/items.yaml": {
        Item: {
          type: "object",
          properties: { child: { $ref: "../openapi.yaml#/components/schemas/Item" } },
        },
      },
    });
    const graph = await new ContractGraph({ fixture: files["openapi.yaml"] }).load();
    const bundle = graph.bundle("fixture");
    expect(bundle).toEqual(graph.bundle("fixture"));
    expect(record(record(bundle.paths)["/v1/items"]).description).toBe("path description");
    expect(JSON.stringify(bundle)).not.toContain("items.yaml");
    expect(JSON.stringify(bundle)).toContain("#/components/schemas/Item");
    expect(operationInventory(bundle)).toEqual([
      { method: "get", path: "/v1/items", operationId: "getItems" },
    ]);
  });

  it.each([
    ["file", "missing.yaml#/Item"],
    ["pointer", "schemas.yaml#/Missing"],
  ])("rejects a missing %s even in an unused schema", async (_kind, reference) => {
    const files = await fixture({
      "openapi.yaml": document({}, { Unused: { $ref: reference } }),
      "schemas.yaml": { Item: { type: "string" } },
    });
    await expect(new ContractGraph({ fixture: files["openapi.yaml"] }).load()).rejects.toThrow();
  });

  it("rejects duplicate YAML keys and duplicate operation IDs", async () => {
    const files = await fixture({
      "openapi.yaml":
        "openapi: 3.1.0\npaths: {}\ncomponents:\n  schemas:\n    Item: {type: string}\n    Item: {type: integer}\n",
    });
    await expect(new ContractGraph({ fixture: files["openapi.yaml"] }).load()).rejects.toThrow();
    expect(() =>
      operationInventory(
        document({
          "/one": { get: { operationId: "same" } },
          "/two": { post: { operationId: "same" } },
        }),
      ),
    ).toThrow("duplicate operationId");
  });

  it("rejects conflicting browser component names instead of silently overwriting them", async () => {
    const files = await fixture({
      "one/openapi.yaml": document({}, { Item: { type: "string" } }),
      "two/openapi.yaml": document({}, { Item: { type: "integer" } }),
    });
    const graph = await new ContractGraph({
      one: files["one/openapi.yaml"],
      two: files["two/openapi.yaml"],
    }).load();
    expect(() => graph.browserBundle("two", ["one"])).toThrow("conflicting component names");
  });

  it("preserves cross-contract names and Go import references", async () => {
    const files = await fixture({
      "one/openapi.yaml": document({}, { Item: { $ref: "schemas/item.yaml#/Item" } }),
      "one/schemas/item.yaml": { Item: { type: "string" } },
      "two/openapi.yaml": document(
        {},
        { Other: { $ref: "../one/openapi.yaml#/components/schemas/Item" } },
      ),
    });
    const graph = await new ContractGraph({
      one: files["one/openapi.yaml"],
      two: files["two/openapi.yaml"],
    }).load();
    expect(record(record(graph.bundle("two").components).schemas).Other).toEqual({
      $ref: "one.yaml#/components/schemas/Item",
    });
    expect(record(record(graph.browserBundle("two", ["one"]).components).schemas).Other).toEqual({
      $ref: "#/components/schemas/Item",
    });
  });

  it("retains authored aliases through nested schema fragments and URI-escaped filenames", async () => {
    const files = await fixture({
      "openapi.yaml": document(
        {},
        { ID: { $ref: "schemas/outer.yaml#/ID" }, Alias: { $ref: "schemas/alias.yaml#/Alias" } },
      ),
      "schemas/outer.yaml": { ID: { $ref: "inner%20schema.yaml#/definitions/ID" } },
      "schemas/inner schema.yaml": { definitions: { ID: { type: "string" } } },
      "schemas/alias.yaml": { Alias: { $ref: "../openapi.yaml#/components/schemas/ID" } },
    });
    const graph = await new ContractGraph({ fixture: files["openapi.yaml"] }).load();
    expect(record(record(graph.bundle("fixture").components).schemas)).toEqual({
      ID: { type: "string" },
      Alias: { $ref: "#/components/schemas/ID" },
    });
  });

  it("rejects two public component names for the same fragment definition", async () => {
    const files = await fixture({
      "openapi.yaml": document(
        {},
        { One: { $ref: "schemas.yaml#/Item" }, Two: { $ref: "schemas.yaml#/Item" } },
      ),
      "schemas.yaml": { Item: { type: "string" } },
    });
    await expect(new ContractGraph({ fixture: files["openapi.yaml"] }).load()).rejects.toThrow(
      "conflicting component names",
    );
  });

  it("rejects fragment-only cycles while allowing named schema recursion", async () => {
    const files = await fixture({
      "openapi.yaml": document({ "/cycle": { $ref: "a.yaml#/item" } }),
      "a.yaml": { item: { $ref: "b.yaml#/item" } },
      "b.yaml": { item: { $ref: "a.yaml#/item" } },
    });
    await expect(
      (async () =>
        (await new ContractGraph({ fixture: files["openapi.yaml"] }).load()).bundle("fixture"))(),
    ).rejects.toThrow("cyclic OpenAPI fragment reference");
  });

  it("does not contact remote reference servers", async () => {
    let requests = 0;
    const server = createServer((_request, response) => {
      requests++;
      response.end("{}");
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    try {
      const address = server.address();
      if (!address || typeof address === "string") throw new Error("expected a TCP listener");
      const files = await fixture({
        "openapi.yaml": document(
          {},
          { Remote: { $ref: `http://127.0.0.1:${address.port}/remote.json` } },
        ),
      });
      await expect(new ContractGraph({ fixture: files["openapi.yaml"] }).load()).rejects.toThrow();
      expect(requests).toBe(0);
    } finally {
      await new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      );
    }
  });
});

describe("contract move inventory", () => {
  it("exports deterministic portable bundles without running code generation", async () => {
    const directory = await mkdtemp(join(tmpdir(), "tnl-openapi-export-"));
    directories.push(directory);
    const args = [join(root, "scripts/generate/openapi.ts"), "--bundle-dir", directory];
    execFileSync(process.execPath, args, { cwd: root, stdio: "pipe" });
    const first = await Promise.all(
      Object.keys(contracts).map((name) => readFile(join(directory, `${name}.yaml`), "utf8")),
    );
    execFileSync(process.execPath, args, { cwd: root, stdio: "pipe" });
    expect(
      await Promise.all(
        Object.keys(contracts).map((name) => readFile(join(directory, `${name}.yaml`), "utf8")),
      ),
    ).toEqual(first);
    const exported = await new ContractGraph(
      Object.fromEntries(
        Object.keys(contracts).map((name) => [name, join(directory, `${name}.yaml`)]),
      ),
    ).load();
    const source = await repositoryGraph();
    for (const name of Object.keys(contracts))
      expect(exported.bundle(name), name).toEqual(source.bundle(name));
  });

  it("preserves every operation, schema, and complete bundled contract from bc1efd09", async () => {
    const after = await repositoryGraph();
    const inventory = record(
      JSON.parse(await readFile(join(root, "api/fixtures/openapi-inventory/v1.json"), "utf8")),
    );
    expect(inventory.baseline).toBe("bc1efd09");
    for (const name of Object.keys(contracts)) {
      const moved = after.bundle(name);
      const saved = record(record(inventory.contracts)[name]);
      expect(operationInventory(moved), name).toEqual(saved.operations);
      expect(Object.keys(record(record(moved.components).schemas)), name).toEqual(saved.schemas);
      expect(hash(moved), name).toBe(saved.contractSHA256);
    }
    expect(hash(after.browserBundle("publisherv1", ["controlv1"]))).toBe(
      record(inventory.browser).contractSHA256,
    );
  });

  it("retains the baseline's required generated public type and browser export names", async () => {
    const inventory = record(
      JSON.parse(await readFile(join(root, "api/fixtures/openapi-inventory/v1.json"), "utf8")),
    );
    const declarations = record(
      JSON.parse(
        await readFile(join(root, "api/fixtures/openapi-inventory/public-types-v1.json"), "utf8"),
      ),
    );
    for (const name of Object.keys(contracts)) {
      const source = await readFile(join(root, "pkg/api", name, "openapi.gen.go"), "utf8");
      const names = [...source.matchAll(/^type ([A-Z]\w*)\b/gm)].map((match) => match[1]);
      expect(names, name).toEqual(record(record(inventory.contracts)[name]).publicTypes);
      const types = [...source.matchAll(/^type [A-Z]\w*(?:[^\n]*\{[\s\S]*?^\}|[^\n]*)/gm)]
        .map((match) => match[0])
        .join("\n");
      expect(createHash("sha256").update(types).digest("hex"), name).toBe(
        record(declarations.packages)[name],
      );
      const registrations = source
        .split("\n")
        .filter((line) => line.startsWith("\tm.HandleFunc("))
        .join("\n");
      expect(createHash("sha256").update(registrations).digest("hex"), name).toBe(
        record(declarations.registrations)[name],
      );
    }
    const source = await readFile(join(root, "internal/publisher/browserapi/model.gen.ts"), "utf8");
    const names = [...source.matchAll(/^export (?:type|const|interface) ([A-Za-z]\w*)\b/gm)].map(
      (match) => match[1],
    );
    expect(names).toEqual(record(inventory.browser).publicExports);
    expect(
      createHash("sha256")
        .update(source.replace(/^\/\/ generated from [^\n]*\n/, ""))
        .digest("hex"),
    ).toBe(declarations.browserModelSHA256);
  });
});
import { execFileSync } from "node:child_process";
