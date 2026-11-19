import { connect, deployment, publish } from "@tnldotdev/tnl/browser";
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
    services: {
      web: { protocol: "http" },
      restricted: { protocol: "http" },
      private: { protocol: "http" },
      exact: { protocol: "http" },
    },
  } as const;
  const publisher = deployment(fixture.deployment, options);
  const siblingPublisher = deployment(fixture.deployment, {
    ...options,
    token: fixture.sibling_token,
  });
  // a distinct deployment owns another actual go runtime for connector traffic.
  const connector = deployment(fixture.deployment, {
    project: fixture.project,
    token: fixture.token,
    services: { web: { protocol: "http" }, private: { protocol: "http" } },
  });
  const publisherRuntime = crypto.randomUUID();
  const handler = publisherHandler(publisherRuntime);
  const restrictedHandler = publisherHandler(crypto.randomUUID());
  let phase = "publish";
  const step = (value: string) => {
    phase = value;
    console.info(`publisher fixture phase: ${value}`);
  };
  const operation = async () => {
    step("publish");
    const publication = await publish(publisher, "web", handler.handle);
    check(publication.url === fixture.named_url, "public publication has the wrong URL");
    check(
      publication.run !== undefined && publication.publisherURL === undefined,
      "canonical-only publication lost its run metadata or enabled an alias implicitly",
    );
    step("public-exercise");
    const publicProof = await fixtureCall(fixture, "/exercise", publication.url);
    const exported = await publication.exportCertificate();
    const firstPEM = /-----BEGIN CERTIFICATE-----([\s\S]+?)-----END CERTIFICATE-----/.exec(
      exported.certificate.certificatePEM,
    )?.[1];
    check(firstPEM !== undefined, "export did not include the installed leaf");
    const leafDER = Uint8Array.from(atob(firstPEM.replaceAll(/\s/g, "")), (c) => c.charCodeAt(0));
    const fingerprint = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", leafDER)))
      .map((value) => value.toString(16).padStart(2, "0"))
      .join("");
    check(
      publicProof.status === 200 &&
        publicProof.body === "portable-publisher" &&
        publicProof.certificate_sha256 === fingerprint &&
        exported.expiresAt > Date.now(),
      "public visitor did not verify the exported publisher certificate",
    );
    step("exact-run-exercise");
    const exactRuntime = crypto.randomUUID();
    const exactHandler = publisherHandler(exactRuntime);
    const exactPublication = await publish(publisher, "exact", exactHandler.handle);
    const { publisherURL, run } = exactPublication;
    check(
      publisherURL !== undefined && run !== undefined && publisherURL !== exactPublication.url,
      "publication omitted its exact-run address or immutable run metadata",
    );
    const exactCanonical = await fixtureCall(fixture, "/observe", exactPublication.url);
    const aliasProof = await fixtureCall(fixture, "/exercise", publisherURL);
    check(
      aliasProof.status === 200 &&
        aliasProof.service_id === run.serviceID &&
        aliasProof.service_run_id === run.serviceRunID &&
        String(aliasProof.run_number) === run.runNumber &&
        aliasProof.publisher_runtime === exactRuntime &&
        aliasProof.certificate_sha256 === exactCanonical.certificate_sha256,
      "exact-run address lost its assigned run, handler, or verified service certificate",
    );
    step("connector");
    const connection = await connect(connector, "web");
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
    const restricted = await publish(publisher, "restricted", restrictedHandler.handle);
    check(restricted.url === fixture.restricted_url, "restricted publication has the wrong URL");
    const denied = await fixtureCall(fixture, "/observe", restricted.url);
    check(
      denied.status === 403 && restrictedHandler.calls() === 0,
      "restricted public request reached the handler",
    );

    step("private");
    const privatePublication = await publish(publisher, "private", handler.handle);
    check(!("url" in privatePublication), "private publication exposed a public URL");
    const privateConnection = await connect(connector, "private");
    const privateResponse = await privateConnection.fetch("/probe");
    check(
      privateResponse.status === 200 && (await privateResponse.text()) === "portable-publisher",
      "authorized connector could not reach the private publication",
    );
    const privateState = await fixtureCall(fixture, "/state", `https://${fixture.private_host}`);
    check(privateState.active_runs === 1, "private publication did not keep a ready service run");
    // join the connector's own stream and pair retirement before taking down
    // its peer. relay loss and retained-session shutdown are tested separately.
    step("connector-close");
    await connector.close();

    step("alias-sibling");
    const siblingRuntime = crypto.randomUUID();
    const siblingHandler = publisherHandler(siblingRuntime);
    const sibling = await publish(siblingPublisher, "exact", siblingHandler.handle);
    check(
      sibling.publisherURL !== undefined &&
        sibling.run !== undefined &&
        sibling.publisherURL !== publisherURL &&
        sibling.run.serviceID === run.serviceID &&
        sibling.run.serviceRunID !== run.serviceRunID,
      "sibling publication reused another exact-run binding",
    );
    const siblingProof = await fixtureCall(fixture, "/observe", sibling.publisherURL);
    check(
      siblingProof.status === 200 && siblingProof.publisher_runtime === siblingRuntime,
      "sibling alias selected another publisher",
    );
    step("named-close");
    await privatePublication.close();
    await privatePublication.wait();
    const privateClosed = await fixtureCall(fixture, "/state", `https://${fixture.private_host}`);
    check(
      privateClosed.active_runs === 0 && !privateClosed.deleted,
      "private publication cleanup changed the retained service",
    );
    await restricted.close();
    await restricted.wait();
    await publication.close();
    await publication.wait();
    let closedExport = false;
    try {
      await publication.exportCertificate();
    } catch (error) {
      closedExport =
        typeof error === "object" &&
        error !== null &&
        "code" in error &&
        error.code === "sdk.certificate_unavailable";
    }
    check(closedExport, "closed browser publication could still export a certificate");
    await exactPublication.close();
    await exactPublication.wait();
    step("alias-no-fallback");
    const callsBefore = siblingHandler.calls();
    const unavailable = await fixtureCall(fixture, "/unavailable", publisherURL);
    check(
      unavailable.status !== 200 &&
        unavailable.active_runs === 1 &&
        siblingHandler.calls() === callsBefore,
      "closed exact-run address fell back to a live sibling",
    );
    const pooled = await fixtureCall(fixture, "/observe", exactPublication.url);
    check(
      pooled.status === 200 && pooled.publisher_runtime === siblingRuntime,
      "closing one alias interrupted the pooled sibling endpoint",
    );
    await sibling.close();
    await sibling.wait();
    const named = await fixtureCall(fixture, "/state", publication.url);
    check(
      named.active_runs === 0 && !named.deleted,
      "named publication cleanup removed its saved service or retained a run",
    );

    step("temporary");
    const temporary = await publish(publisher, handler.handle, { access: "anonymous" });
    check(temporary.url !== undefined, "public temporary publication omitted its URL");
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
    const privateTemporary = await publish(publisher, handler.handle, { public: false });
    check(!("url" in privateTemporary), "private temporary publication exposed a public URL");
    await privateTemporary.close();
    await privateTemporary.wait();
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
      connectorOnlyPublication: true,
      connectorOnlyTemporary: true,
      exactRunAliases: true,
      noSiblingFallback: true,
      joined: true,
      runtimes: runtimeStarts(),
    };
  };
  const [result] = await Promise.allSettled([operation()]);
  console.info("publisher fixture phase: cleanup");
  const cleanup = await Promise.allSettled([
    connector.close(),
    siblingPublisher.close(),
    publisher.close(),
  ]);
  const failures = [
    ...(result?.status === "rejected" ? publisherFailures(result.reason, phase) : []),
    ...cleanup.flatMap((entry, index) =>
      entry.status === "rejected"
        ? publisherFailures(entry.reason, index === 0 ? "connector-close" : "publisher-close")
        : [],
    ),
  ];
  if (failures.length > 0) throw new Error(JSON.stringify(failures));
  check(result?.status === "fulfilled", "publisher proof did not complete");
  return result.value;
}
