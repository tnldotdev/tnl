import { $RefParser } from "@apidevtools/json-schema-ref-parser";
import type { FileInfo } from "@apidevtools/json-schema-ref-parser";
import { execFileSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parseDocument, stringify } from "yaml";

export const root = fileURLToPath(new URL("../../", import.meta.url));

// models must exist before the internal generators compile against these packages.
export const contracts = {
  controlv1: "api/control/public/v1/openapi.yaml",
  authorityv1: "api/control/authority/v1/openapi.yaml",
  ingressv1: "api/control/private/ingress/v1/openapi.yaml",
  relayv1: "api/control/private/relay/v1/openapi.yaml",
  publicurlusagev1: "api/integrations/public-url-usage/v1/openapi.yaml",
  publisherv1: "api/publisher/browser/v1/openapi.yaml",
  localpublisherv1: "api/publisher/local/v1/openapi.yaml",
} as const;

export const packagePaths: Record<keyof typeof contracts, string> = {
  controlv1: "control/public/v1",
  authorityv1: "control/authority/v1",
  ingressv1: "control/private/ingress/v1",
  relayv1: "control/private/relay/v1",
  publicurlusagev1: "integrations/public-url-usage/v1",
  publisherv1: "publisher/browser/v1",
  localpublisherv1: "publisher/local/v1",
};

export function record(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("expected an OpenAPI object");
  }
  return value as Record<string, unknown>;
}

function target(reference: string, source: string): string {
  if (/^[a-z][a-z\d+.-]*:/i.test(reference) || reference.startsWith("//")) {
    throw new Error(`OpenAPI references must be offline file references: ${reference}`);
  }
  const url = new URL(reference, pathToFileURL(source.replace(/#.*$/, "")));
  const pointer = url.hash.slice(1);
  if (pointer !== "" && !pointer.startsWith("/")) {
    throw new Error(`expected a JSON pointer: ${reference}`);
  }
  return `${fileURLToPath(url)}#${pointer}`;
}

function visit(value: unknown, callback: (object: Record<string, unknown>) => void): void {
  if (Array.isArray(value)) {
    value.forEach((item) => visit(item, callback));
  } else if (value !== null && typeof value === "object") {
    const object = record(value);
    callback(object);
    Object.values(object).forEach((item) => visit(item, callback));
  }
}

export type Operation = { method: string; path: string; operationId: string };
const methods = new Set(["get", "put", "post", "delete", "options", "head", "patch", "trace"]);

export function operationInventory(document: unknown): Operation[] {
  const operations: Operation[] = [];
  const ids = new Set<string>();
  for (const [path, item] of Object.entries(record(record(document).paths))) {
    for (const [method, value] of Object.entries(record(item))) {
      if (!methods.has(method)) continue;
      const { operationId } = record(value);
      if (typeof operationId !== "string" || operationId.length === 0) {
        throw new Error(`missing operationId: ${method} ${path}`);
      }
      if (ids.has(operationId)) throw new Error(`duplicate operationId: ${operationId}`);
      ids.add(operationId);
      operations.push({ method, path, operationId });
    }
  }
  return operations.sort((a, b) =>
    `${a.path} ${a.method}`.localeCompare(`${b.path} ${b.method}`, "en"),
  );
}

// ref-parser owns file loading and JSON-pointer resolution. this adapter keeps
// named components instead of letting first-use locations rename public types.
export class ContractGraph {
  readonly parser = new $RefParser();
  readonly entries: Record<string, string>;
  readonly components = new Map<string, { owner: string; pointer: string }>();

  constructor(entries: Record<string, string>) {
    this.entries = Object.fromEntries(
      Object.entries(entries).map(([name, file]) => [name, resolve(file)]),
    );
  }

  private localFragment(coordinate: string, file: string): boolean {
    return (
      coordinate.startsWith(`${dirname(file)}/`) &&
      !Object.values(this.entries).some((entry) => coordinate.startsWith(`${entry}#`))
    );
  }

  private referencedValue(coordinate: string): unknown {
    // get() follows a terminal $ref too. resolve its parent with ref-parser and
    // retain the last property's authored alias, which is part of the Go API.
    const slash = coordinate.lastIndexOf("/");
    if (slash < coordinate.indexOf("#")) return this.parser.$refs.get(coordinate);
    const value: unknown = this.parser.$refs.get(coordinate.slice(0, slash));
    const parent = Array.isArray(value)
      ? Object.fromEntries(value.map((item: unknown, index: number) => [String(index), item]))
      : record(value);
    const key = decodeURIComponent(coordinate.slice(slash + 1))
      .replaceAll("~1", "/")
      .replaceAll("~0", "~");
    if (!Object.hasOwn(parent, key)) throw new Error(`missing OpenAPI reference: ${coordinate}`);
    return parent[key];
  }

  async load(): Promise<this> {
    await this.parser.resolve(
      { allOf: Object.values(this.entries).map((file) => ({ $ref: file })) },
      {
        resolve: { http: false },
        parse: {
          yaml: {
            order: 1,
            canParse: [".yaml", ".yml"],
            parse: (file: FileInfo) => {
              const document = parseDocument(String(file.data), { uniqueKeys: true });
              if (document.errors.length) throw document.errors[0];
              return document.toJS() as unknown;
            },
          },
        },
      },
    );
    // resolve() loads files; get() also checks every pointer, including references
    // in unused schemas. remote readers are disabled before any file is loaded.
    for (const file of this.parser.$refs.paths()) {
      visit(this.parser.$refs.get(file), (object) => {
        if (typeof object.$ref === "string") this.parser.$refs.get(target(object.$ref, file));
      });
    }
    for (const [owner, file] of Object.entries(this.entries)) {
      const document = record(this.parser.$refs.get(file));
      for (const [kind, items] of Object.entries(record(document.components ?? {}))) {
        for (const [name, value] of Object.entries(record(items))) {
          const pointer = `/components/${kind}/${name.replaceAll("~", "~0").replaceAll("/", "~1")}`;
          this.components.set(`${file}#${pointer}`, { owner, pointer });
          let definition = value;
          let source = file;
          const seen = new Set<string>();
          while (definition !== null && typeof definition === "object") {
            const reference = record(definition).$ref;
            if (typeof reference !== "string") break;
            const coordinate = target(reference, source);
            // external and root-level aliases keep their authoritative names.
            if (!this.localFragment(coordinate, file)) break;
            if (seen.has(coordinate))
              throw new Error(`cyclic OpenAPI fragment reference: ${coordinate}`);
            seen.add(coordinate);
            const existing = this.components.get(coordinate);
            if (existing && (existing.owner !== owner || existing.pointer !== pointer)) {
              throw new Error(`conflicting component names: ${coordinate}`);
            }
            this.components.set(coordinate, { owner, pointer });
            definition = this.referencedValue(coordinate);
            source = coordinate;
          }
        }
      }
    }
    return this;
  }

  bundle(owner: string): Record<string, unknown> {
    const file = this.entries[owner];
    if (!file) throw new Error(`unknown OpenAPI contract: ${owner}`);
    const expand = (
      value: unknown,
      source: string,
      stack: Set<string>,
      unwrap = false,
    ): unknown => {
      if (Array.isArray(value)) return value.map((item) => expand(item, source, stack));
      if (value === null || typeof value !== "object") return value;
      const object = record(value);
      if (typeof object.$ref === "string") {
        const coordinate = target(object.$ref, source);
        const named = this.components.get(coordinate);
        const canonical = named && coordinate === `${this.entries[named.owner]}#${named.pointer}`;
        if (named && (!unwrap || canonical)) {
          return {
            ...Object.fromEntries(
              Object.entries(object)
                .filter(([key]) => key !== "$ref")
                .map(([key, item]) => [key, expand(item, source, stack)]),
            ),
            $ref: `${named.owner === owner ? "" : `${named.owner}.yaml`}#${named.pointer}`,
          };
        }
        if (stack.has(coordinate))
          throw new Error(`cyclic OpenAPI fragment reference: ${coordinate}`);
        const next = new Set(stack).add(coordinate);
        const resolved = expand(this.referencedValue(coordinate), coordinate, next, unwrap);
        const siblings = Object.fromEntries(
          Object.entries(object)
            .filter(([key]) => key !== "$ref")
            .map(([key, item]) => [key, expand(item, source, stack)]),
        );
        return Object.keys(siblings).length ? { ...record(resolved), ...siblings } : resolved;
      }
      return Object.fromEntries(
        Object.entries(object).map(([key, item]) => [key, expand(item, source, stack)]),
      );
    };
    const document = record(this.parser.$refs.get(file));
    const bundled = {
      ...Object.fromEntries(
        Object.entries(document)
          .filter(([key]) => key !== "components" && key !== "paths")
          .map(([key, value]) => [key, expand(value, file, new Set())]),
      ),
      paths: Object.fromEntries(
        Object.entries(record(document.paths)).map(([path, value]) => [
          path,
          expand(value, file, new Set(), true),
        ]),
      ),
      components: Object.fromEntries(
        Object.entries(record(document.components ?? {})).map(([kind, values]) => [
          kind,
          Object.fromEntries(
            Object.entries(record(values)).map(([name, value]) => {
              const reference =
                value !== null && typeof value === "object" ? record(value).$ref : undefined;
              const coordinate = typeof reference === "string" ? target(reference, file) : "";
              const localFragment = this.localFragment(coordinate, file);
              return [name, expand(value, file, new Set(), localFragment)];
            }),
          ),
        ]),
      ),
    };
    operationInventory(bundled);
    return bundled;
  }

  browserBundle(owner: string, dependencies: string[]): Record<string, unknown> {
    const document = this.bundle(owner);
    const schemas: Record<string, unknown> = {};
    const localize = (value: unknown): unknown => {
      if (Array.isArray(value)) return value.map(localize);
      if (value === null || typeof value !== "object") return value;
      return Object.fromEntries(
        Object.entries(record(value)).map(([key, item]) => {
          if (key === "$ref" && typeof item === "string" && !item.startsWith("#")) {
            const hash = item.indexOf("#");
            const file = item.slice(0, hash);
            const pointer = item.slice(hash + 1);
            if (
              !dependencies.includes(file.replace(/\.yaml$/, "")) ||
              !pointer.startsWith("/components/schemas/")
            ) {
              throw new Error(`unavailable browser component: ${item}`);
            }
            return [key, `#${pointer}`];
          }
          return [key, localize(item)];
        }),
      );
    };
    for (const name of [...dependencies, owner]) {
      const source = record(record(this.bundle(name).components).schemas);
      for (const [key, value] of Object.entries(source)) {
        const localized = localize(value);
        if (
          Object.hasOwn(schemas, key) &&
          JSON.stringify(schemas[key]) !== JSON.stringify(localized)
        ) {
          throw new Error(`conflicting component names: ${key}`);
        }
        schemas[key] = localized;
      }
    }
    return record(
      localize({ ...document, components: { ...record(document.components), schemas } }),
    );
  }
}

export async function repositoryGraph(): Promise<ContractGraph> {
  return new ContractGraph(
    Object.fromEntries(Object.entries(contracts).map(([name, file]) => [name, join(root, file)])),
  ).load();
}

async function main(): Promise<void> {
  const requested = process.argv.slice(2);
  if (requested[0] === "--bundle-dir") {
    const directory = requested[1];
    if (!directory || requested.length !== 2) throw new Error("expected --bundle-dir DIRECTORY");
    const graph = await repositoryGraph();
    await mkdir(directory, { recursive: true });
    for (const name of Object.keys(contracts)) {
      await writeFile(
        join(directory, `${name}.yaml`),
        `${JSON.stringify(graph.bundle(name), null, 2)}\n`,
      );
    }
    return;
  }
  if (requested.some((name) => !Object.hasOwn(contracts, name))) {
    throw new Error("expected canonical package names (for example controlv1)");
  }
  const graph = await repositoryGraph();
  const directory = await mkdtemp(join(tmpdir(), "tnl-openapi-"));
  try {
    for (const name of Object.keys(contracts)) {
      // YAML retains path order for oapi-codegen's public mux registration calls.
      await writeFile(join(directory, `${name}.yaml`), stringify(graph.bundle(name)));
    }
    for (const name of Object.keys(contracts).filter(
      (name) => requested.length === 0 || requested.includes(name),
    )) {
      const cwd = join(root, "pkg/api", packagePaths[name as keyof typeof contracts]);
      const configuration = record(
        parseDocument(await readFile(join(cwd, "oapi-codegen.yaml"), "utf8")).toJS(),
      );
      configuration.output = join(cwd, "openapi.gen.go");
      const configPath = join(directory, `${name}.config.yaml`);
      await writeFile(configPath, stringify(configuration));
      execFileSync("oapi-codegen", ["--config", configPath, join(directory, `${name}.yaml`)], {
        cwd: root,
        stdio: "inherit",
      });
      if (["controlv1", "authorityv1", "publisherv1"].includes(name)) {
        execFileSync(
          process.execPath,
          [join(root, "scripts/generate/normalize-openapi-go.ts"), "openapi.gen.go"],
          { cwd, stdio: "inherit" },
        );
      }
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url)
  await main();
