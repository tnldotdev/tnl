import { createClient } from "@hey-api/openapi-python";
import { resolve } from "node:path";
import { root } from "./api-contracts.ts";
import { managementSource } from "./management-sdk.ts";

const { document, operations } = await managementSource();
await createClient({
  input: document,
  output: {
    path: resolve(root, "packages/py/src/tnl/_management"),
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
