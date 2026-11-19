import { publish, publisher } from "@tnldotdev/tnl/browser";
import type * as z from "zod";
import { parseHost } from "../peers/gossip.ts";
import type { hostingConfig } from "../enrollment.ts";

export async function startPublisher(
  config: z.infer<typeof hostingConfig>,
  enrollment: (signal: AbortSignal) => Promise<string>,
  handler: (request: Request) => Promise<Response>,
  signal: AbortSignal,
) {
  const owner = await publisher({
    instance: "keepalive",
    controlUrl: config.controlURL,
    enrollment,
    signal,
  });
  try {
    const publication = await publish(owner, "production", handler, {
      ...(config.certificate === undefined ? {} : { certificate: config.certificate }),
      signal,
    });
    const host = parseHost({
      origin: publication.publisherURL,
      publisherID: owner.publisherIdentityID,
      runID: publication.run?.serviceRunID,
      runNumber: publication.run?.runNumber,
    });
    if (host === undefined) throw new Error("The publication has no host address.");
    return { host, close: () => owner.close(), wait: () => publication.wait() };
  } catch (error) {
    try {
      await owner.close();
    } catch (cleanup) {
      throw new AggregateError([error, cleanup], "Could not stop after startup failed.");
    }
    throw error;
  }
}
