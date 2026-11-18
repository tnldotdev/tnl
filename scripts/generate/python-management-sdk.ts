import { createClient } from "@hey-api/openapi-python";
import { execFileSync } from "node:child_process";
import { writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { record, root } from "./api-contracts.ts";
import { managementSource } from "./management-sdk.ts";

const { document, operations } = await managementSource();
const output = resolve(root, "packages/py/src/tnl/_management");
await createClient({
  input: document,
  output: {
    path: output,
    pythonVersion: "3.12",
    postProcess: [
      {
        command: "uv",
        args: [
          "run",
          "--frozen",
          "--project",
          resolve(root, "packages/py"),
          "ruff",
          "format",
          "{{path}}",
        ],
      },
    ],
  },
  parser: {
    filters: {
      operations: {
        include: operations.map(({ method, path }) => `${method.toUpperCase()} ${path}`),
      },
      parameters: { include: ["TeamIDQuery"] },
      orphans: false,
    },
  },
  plugins: [{ name: "pydantic", enums: "literal" }],
});
const routes = operations
  .map(({ operationId, method, path }) => {
    const responses = record(record(document.paths[path][method]).responses);
    const successes = Object.keys(responses).filter((status) => /^2[0-9]{2}$/.test(status));
    if (successes.length !== 1) throw new Error(`expected one success status for ${operationId}`);
    return `    ${JSON.stringify(operationId)}: (${JSON.stringify(method.toUpperCase())}, ${JSON.stringify(path)}, ${successes[0]}),`;
  })
  .sort();
const routeFile = resolve(output, "operations_gen.py");
await writeFile(
  routeFile,
  `# generated from the public control contract; do not edit.\n\nOPERATIONS: dict[str, tuple[str, str, int]] = {\n${routes.join("\n")}\n}\n`,
);
execFileSync(
  "uv",
  ["run", "--frozen", "--project", resolve(root, "packages/py"), "ruff", "format", routeFile],
  { stdio: "inherit" },
);
