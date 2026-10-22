import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { repositoryGraph } from "./openapi.ts";

const root = fileURLToPath(new URL("../../", import.meta.url));
const output = fileURLToPath(
  new URL("../../internal/publisher/browserapi/model.gen.ts", import.meta.url),
);

const graph = await repositoryGraph();
const bundled = graph.browserBundle("publisherv1", ["controlv1"]);
const temporary = mkdtempSync(join(tmpdir(), "tnl-publisher-contract-"));
try {
  const specification = join(temporary, "openapi.json");
  writeFileSync(specification, JSON.stringify(bundled));
  execFileSync(
    "pnpm",
    [
      "exec",
      "typed-openapi",
      specification,
      "--output",
      output,
      "--runtime",
      "zod",
      "--validation",
      "strict",
      "--tree-shake-schemas",
      "--schemas-only",
      "--no-runtime-types",
    ],
    { cwd: root, stdio: "inherit" },
  );
} finally {
  rmSync(temporary, { recursive: true, force: true });
}
const generated = readFileSync(output, "utf8");
const formatted = execFileSync("pnpm", ["exec", "oxfmt", "--stdin-filepath", output], {
  cwd: root,
  input: "// generated from api/publisher/browser/v1/openapi.yaml; do not edit.\n" + generated,
  encoding: "utf8",
});
writeFileSync(output, formatted);
