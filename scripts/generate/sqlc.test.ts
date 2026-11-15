import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rename,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, it } from "vitest";
import { generateSQL } from "./sqlc.ts";

const directories: string[] = [];
afterEach(async () => {
  for (const directory of directories.splice(0))
    await rm(directory, { recursive: true, force: true });
});

async function fixture(engine: "sqlite" | "postgresql" = "sqlite"): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), "tnl-sqlc-test-"));
  directories.push(directory);
  await mkdir(join(directory, "queries"));
  await writeFile(join(directory, "schema.sql"), "CREATE TABLE items (id INTEGER PRIMARY KEY);\n");
  await writeFile(
    join(directory, "queries", "items.sql"),
    `-- name: GetItem :one\nSELECT id FROM items WHERE id = ${engine === "sqlite" ? "?" : "$1"};\n`,
  );
  await writeFile(
    join(directory, "sqlc.yaml"),
    `version: "2"
sql:
  - engine: ${engine}
    schema: ${engine === "sqlite" ? "schema.sql" : "[schema.sql]"}
    queries: ${engine === "sqlite" ? "queries" : "[queries]"}
    gen:
      go:
        package: itemsdb
        out: generated
        sql_package: ${engine === "sqlite" ? "database/sql" : "pgx/v5"}
`,
  );
  return directory;
}

it.each(["sqlite", "postgresql"] as const)(
  "keeps %s output current without removing handwritten files",
  async (engine) => {
    const directory = await fixture(engine);
    const config = join(directory, "sqlc.yaml");
    const output = join(directory, "generated");
    await generateSQL(config);
    await writeFile(join(output, "handwritten.go"), "package itemsdb\n");
    await rename(
      join(directory, "queries", "items.sql"),
      join(directory, "queries", "selected.sql"),
    );
    await generateSQL(config);
    const names = (await readdir(output)).sort();
    expect(names).toContain("selected.sql.go");
    expect(names).not.toContain("items.sql.go");
    expect(await readFile(join(output, "handwritten.go"), "utf8")).toBe("package itemsdb\n");
    const before = await Promise.all(names.map((name) => readFile(join(output, name), "utf8")));
    await generateSQL(config);
    expect((await readdir(output)).sort()).toEqual(names);
    expect(await Promise.all(names.map((name) => readFile(join(output, name), "utf8")))).toEqual(
      before,
    );
  },
);

it("does not change committed output when SQL generation fails", async () => {
  const directory = await fixture();
  const config = join(directory, "sqlc.yaml");
  await generateSQL(config);
  const path = join(directory, "generated", "items.sql.go");
  const before = await readFile(path, "utf8");
  await writeFile(join(directory, "queries", "items.sql"), "-- name: GetItem :one\nINVALID SQL;\n");
  await expect(generateSQL(config)).rejects.toThrow();
  expect(await readFile(path, "utf8")).toBe(before);
});

it("refuses to overwrite a handwritten file that collides with generated output", async () => {
  const directory = await fixture();
  await mkdir(join(directory, "generated"));
  const path = join(directory, "generated", "items.sql.go");
  await writeFile(path, "package itemsdb\n");
  await expect(generateSQL(join(directory, "sqlc.yaml"))).rejects.toThrow("handwritten");
  expect(await readFile(path, "utf8")).toBe("package itemsdb\n");
});

it("does not follow a generated-output symlink into a handwritten file", async () => {
  const directory = await fixture();
  await mkdir(join(directory, "generated"));
  const handwritten = join(directory, "handwritten.go");
  await writeFile(handwritten, "package itemsdb\n");
  await symlink(handwritten, join(directory, "generated", "items.sql.go"));
  await expect(generateSQL(join(directory, "sqlc.yaml"))).rejects.toThrow("non-file");
  expect(await readFile(handwritten, "utf8")).toBe("package itemsdb\n");
});
