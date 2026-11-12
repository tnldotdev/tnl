import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { root, repositoryGraph } from "./api-contracts.ts";

const graph = await repositoryGraph();
const document = graph.bundle("telemetryv1");
const destination = join(root, "pkg/api/integrations/telemetry/v1");
const validation = join(destination, "validation.gen.json");
writeFileSync(
  validation,
  execFileSync("pnpm", ["exec", "oxfmt", "--stdin-filepath", validation], {
    cwd: root,
    input: JSON.stringify(document, null, 2) + "\n",
    encoding: "utf8",
  }),
);
const temporary = mkdtempSync(join(tmpdir(), "tnl-telemetry-"));
try {
  const source = join(temporary, "openapi.json");
  writeFileSync(source, JSON.stringify(document));
  const output = join(destination, "model.gen.ts");
  execFileSync(
    "pnpm",
    [
      "exec",
      "typed-openapi",
      source,
      "--output",
      output,
      "--runtime",
      "zod",
      "--validation",
      "strict",
      "--schemas-only",
      "--no-runtime-types",
    ],
    { cwd: root, stdio: "inherit" },
  );
  const formatted = execFileSync("pnpm", ["exec", "oxfmt", "--stdin-filepath", output], {
    cwd: root,
    input:
      "// generated from contracts/integrations/telemetry/v1; do not edit.\n" +
      readFileSync(output, "utf8"),
    encoding: "utf8",
  });
  writeFileSync(output, formatted);
} finally {
  rmSync(temporary, { recursive: true, force: true });
}
