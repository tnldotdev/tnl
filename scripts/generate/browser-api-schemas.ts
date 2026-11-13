import { fileURLToPath } from "node:url";
import { repositoryGraph } from "./api-contracts.ts";
import { generateValidators } from "./hey-api.ts";

const output = fileURLToPath(
  new URL("../../internal/publisher/browserapi/model.gen.ts", import.meta.url),
);

const graph = await repositoryGraph();
const bundled = graph.browserBundle("publisherv1", ["controlv1"]);
await generateValidators(bundled, output, "contracts/publisher/browser/v1/openapi.yaml", {
  filters: {
    orphans: false,
    // retain path-item parameters as well as operation-level parameters.
    parameters: { include: ["FeedbackID", "IdempotencyKey"] },
  },
});
