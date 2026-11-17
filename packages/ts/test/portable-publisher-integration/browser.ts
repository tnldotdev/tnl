import { createClient } from "@tnldotdev/tnl";
import * as z from "zod";
import { check, fixtureCall, fixtureSchema, publisherFailures } from "./fixture.ts";
import { publisherHandler } from "./handler.ts";
import { installPublisherFixtureHost, runtimeStarts } from "./host.ts";

export async function smoke(input: unknown) {
  check(
    globalThis.isSecureContext && location.protocol === "https:",
    "publisher must run in an actual HTTPS browser context",
  );
  const fixture = fixtureSchema.parse(input);
  installPublisherFixtureHost(fixture);
  const options = {
    project: fixture.project,
    token: fixture.token,
    services: { web: { protocol: "http" }, restricted: { protocol: "http" } },
  } as const;
  const publisher = createClient(options).deployment(fixture.deployment);
  // a distinct deployment owns another actual go runtime for connector traffic.
  const connector = createClient({
    project: fixture.project,
    token: fixture.token,
    services: { web: { protocol: "http" } },
  }).deployment(fixture.deployment);
  const handler = publisherHandler(crypto.randomUUID());
  const restrictedHandler = publisherHandler(crypto.randomUUID());
  let phase = "publish";
  const step = (value: string) => {
    phase = value;
    console.info(`publisher fixture phase: ${value}`);
  };
  const operation = async () => {
    step("publish");
    const publication = await publisher.publish("web", handler.handle);
    step("public-exercise");
    const publicProof = await fixtureCall(fixture, "/exercise", publication.url);
    check(
      publicProof.status === 200 &&
        publicProof.body === "portable-publisher" &&
        publicProof.certificate_sha256.length === 64,
      "public visitor did not verify publisher TLS",
    );
    step("connector");
    const connection = await connector.connect("web");
    step("response-stream");
    const response = await connection.fetch(connection.url + "/stream");
    check(response.ok && response.body !== null, "connector-to-WASM publisher stream failed");
    const reader = response.body.getReader();
    const first = await reader.read();
    check(
      new TextDecoder().decode(first.value) === "first\n" && !first.done,
      "response was buffered instead of streamed",
    );
    const release = await connection.fetch(connection.url + "/release");
    check(
      (await release.text()) === "released",
      "second request did not release the held response",
    );
    const last = await reader.read();
    check(
      new TextDecoder().decode(last.value) === "last\n" && (await reader.read()).done,
      "stream tail changed",
    );
    reader.releaseLock();

    step("upload");
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode("upload-first\n"));
        controller.enqueue(new Uint8Array(128 * 1024).fill(120));
        controller.close();
      },
    });
    const upload = await connection.fetch(connection.url + "/echo", {
      method: "POST",
      headers: { "Content-Type": "application/octet-stream" },
      body,
    });
    step("upload-response");
    check(upload.status === 200, "streamed upload was rejected before the handler");
    const echoed = new Uint8Array(await upload.arrayBuffer());
    step("upload-verify");
    check(
      echoed.length === 13 + 128 * 1024 &&
        new TextDecoder().decode(echoed.subarray(0, 13)) === "upload-first\n" &&
        echoed.subarray(13).every((byte) => byte === 120),
      "streamed request body changed",
    );

    step("cancel");
    const controller = new AbortController();
    const cancel = await connection.fetch(connection.url + "/cancel", {
      signal: controller.signal,
    });
    check(cancel.body !== null, "cancel response has no body");
    const pending = cancel.body.getReader();
    check(
      new TextDecoder().decode((await pending.read()).value) === "cancel-ready\n",
      "cancel stream did not reach handler",
    );
    controller.abort();
    await pending.cancel().catch(() => {});
    pending.releaseLock();
    const evidenceSchema = z.strictObject({
      canceled: z.boolean(),
      requestAborted: z.boolean(),
      calls: z.number().int().positive(),
    });
    // each request observes the actual handler; no timer guesses when go joins
    // the canceled body and forwards its request abort.
    const deadline = AbortSignal.timeout(10_000);
    let canceled = false;
    while (!canceled) {
      deadline.throwIfAborted();
      const evidence = evidenceSchema.parse(
        await (await connection.fetch(connection.url + "/evidence", { signal: deadline })).json(),
      );
      canceled = evidence.canceled && evidence.requestAborted;
    }
    step("restricted");
    const restricted = await publisher.publish("restricted", restrictedHandler.handle);
    const denied = await fixtureCall(fixture, "/observe", restricted.url);
    check(
      denied.status === 403 && restrictedHandler.calls() === 0,
      "restricted public request reached the handler",
    );
    step("named-close");
    await restricted.close();
    await restricted.wait();
    await publication.close();
    await publication.wait();
    const named = await fixtureCall(fixture, "/state", publication.url);
    check(
      named.active_runs === 0 && !named.deleted,
      "named publication cleanup removed its saved service or retained a run",
    );

    step("temporary");
    const temporary = await publisher.publish(handler.handle, { access: "anonymous" });
    const temporaryProof = await fixtureCall(fixture, "/observe", temporary.url);
    check(
      temporaryProof.status === 200 && temporaryProof.body === "portable-publisher",
      "temporary WASM publication was not reachable",
    );
    await temporary.close();
    await temporary.wait();
    const removed = await fixtureCall(fixture, "/state", temporary.url);
    check(
      removed.deleted && removed.active_runs === 0,
      "temporary publication survived joined close",
    );
    check(runtimeStarts() >= 2, "connector and publisher did not use separate actual Go runtimes");
    return {
      actualGoWasm: true,
      httpsBrowser: true,
      named: true,
      temporary: true,
      streamedResponse: true,
      streamedRequest: true,
      publicStreamAndCancel: true,
      canceled: true,
      restrictedDeniedBeforeHandler: true,
      connectorToWasmPublisher: true,
      joined: true,
      runtimes: runtimeStarts(),
    };
  };
  const [result] = await Promise.allSettled([operation()]);
  console.info("publisher fixture phase: cleanup");
  const cleanup = await Promise.allSettled([connector.close(), publisher.close()]);
  const failures = [
    ...(result?.status === "rejected" ? publisherFailures(result.reason, phase) : []),
    ...cleanup.flatMap((entry) =>
      entry.status === "rejected" ? publisherFailures(entry.reason, "cleanup") : [],
    ),
  ];
  if (failures.length > 0) throw new Error(JSON.stringify(failures));
  check(result?.status === "fulfilled", "publisher proof did not complete");
  return result.value;
}
