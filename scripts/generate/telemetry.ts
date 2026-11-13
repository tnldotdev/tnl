import { execFileSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { root, repositoryGraph } from "./api-contracts.ts";
import { generateValidators } from "./hey-api.ts";

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
await generateValidators(
  document,
  join(destination, "model.gen.ts"),
  "contracts/integrations/telemetry/v1/openapi.yaml",
);
