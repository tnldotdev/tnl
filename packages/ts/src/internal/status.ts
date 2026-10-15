import { TnlError } from "../errors.js";
import { exactKeys, record, requiredHostname } from "./runtime.js";
import { allowedKeys } from "./local.js";

export interface PublicationStatus {
  readonly registered: boolean;
  readonly routable: boolean;
  readonly ready: boolean;
  readonly publicURL?: `https://${string}`;
  readonly publishRunNumber?: number;
  readonly failure?: string;
}

export function parseStatus(
  value: unknown,
  service: string,
  registrationID: string,
  target: string,
): PublicationStatus | undefined {
  try {
    const snapshot = record(value, "local publisher snapshot");
    allowedKeys(
      snapshot,
      ["schema_version", "project", "cursor", "observed_at", "services", "publications"],
      "local publisher snapshot",
    );
    if (
      snapshot.schema_version !== 1 ||
      typeof snapshot.project !== "string" ||
      snapshot.project.length > 4096 ||
      typeof snapshot.cursor !== "string" ||
      snapshot.cursor.length > 128 ||
      typeof snapshot.observed_at !== "string" ||
      !Number.isFinite(Date.parse(snapshot.observed_at)) ||
      !Array.isArray(snapshot.services) ||
      snapshot.services.length > 1 ||
      (snapshot.publications !== undefined &&
        (!Array.isArray(snapshot.publications) || snapshot.publications.length > 64))
    )
      throw new TnlError("sdk.response_invalid");
    if (Array.isArray(snapshot.publications))
      for (const raw of snapshot.publications) {
        const publication = record(raw, "publication");
        allowedKeys(
          publication,
          [
            "tunnel_id",
            "command",
            "state",
            "process_id",
            "server",
            "project",
            "service",
            "service_protocol",
            "public_url_id",
            "publish_run_number",
            "public_port",
            "hostname",
            "public_url",
            "target",
            "framework",
            "started_at",
            "updated_at",
            "heartbeat_at",
            "lease_expires_at",
            "failure",
          ],
          "publication",
        );
        if (
          publication.service !== service ||
          !["publish", "dev"].includes(String(publication.command)) ||
          !["starting", "provisioning", "ready", "draining", "stopped", "failed", "stale"].includes(
            String(publication.state),
          ) ||
          typeof publication.process_id !== "number" ||
          !Number.isSafeInteger(publication.process_id)
        )
          throw new TnlError("sdk.response_invalid");
        for (const key of [
          "tunnel_id",
          "server",
          "project",
          "started_at",
          "updated_at",
          "heartbeat_at",
          "lease_expires_at",
        ])
          if (typeof publication[key] !== "string" || (publication[key] as string).length > 4096)
            throw new TnlError("sdk.response_invalid");
        for (const [key, field] of Object.entries(publication)) {
          if (["process_id", "publish_run_number", "public_port"].includes(key)) {
            if (typeof field !== "number" || !Number.isSafeInteger(field) || field < 1)
              throw new TnlError("sdk.response_invalid");
          } else if (typeof field !== "string" || field.length > 4096)
            throw new TnlError("sdk.response_invalid");
        }
      }
    if (snapshot.services.length === 0) return undefined;
    const item = record(snapshot.services[0], "local publisher service");
    allowedKeys(
      item,
      [
        "project",
        "service",
        "service_protocol",
        "directory",
        "tunnel_id",
        "public_url",
        "registration_id",
        "target",
        "framework",
        "registered",
        "routable",
        "ready",
        "publish_run_number",
        "provisioning_stage",
        "readiness",
        "observation",
        "failure",
      ],
      "local publisher service",
    );
    if (
      item.service !== service ||
      (item.service_protocol !== undefined && item.service_protocol !== "http") ||
      typeof item.directory !== "string" ||
      item.directory.length > 4096 ||
      [item.registered, item.routable, item.ready].some((flag) => typeof flag !== "boolean")
    )
      throw new TnlError("sdk.response_invalid");
    for (const key of [
      "project",
      "tunnel_id",
      "registration_id",
      "target",
      "framework",
      "provisioning_stage",
      "failure",
    ]) {
      const field = item[key];
      if (field !== undefined && (typeof field !== "string" || field.length > 4096))
        throw new TnlError("sdk.response_invalid");
    }
    const readiness = record(item.readiness, "readiness");
    exactKeys(readiness, ["path"], "readiness");
    if (
      typeof readiness.path !== "string" ||
      !readiness.path.startsWith("/") ||
      readiness.path.length > 4096
    )
      throw new TnlError("sdk.response_invalid");
    const run = item.publish_run_number;
    if (run !== undefined && (typeof run !== "number" || !Number.isSafeInteger(run) || run < 1))
      throw new TnlError("sdk.response_invalid");
    let publicURL: `https://${string}` | undefined;
    if (item.public_url !== undefined) {
      if (typeof item.public_url !== "string") throw new TnlError("sdk.response_invalid");
      const hostname = requiredHostname(new URL(item.public_url).hostname, "public URL");
      if (item.public_url !== `https://${hostname}`) throw new TnlError("sdk.response_invalid");
      publicURL = `https://${hostname}`;
    }
    if (item.observation !== undefined) {
      const observation = record(item.observation, "readiness observation");
      allowedKeys(
        observation,
        [
          "registration_id",
          "publish_run_number",
          "checked_at",
          "status",
          "ready",
          "reason",
          "readiness",
        ],
        "readiness observation",
      );
      if (
        typeof observation.registration_id !== "string" ||
        typeof observation.publish_run_number !== "number" ||
        !Number.isSafeInteger(observation.publish_run_number) ||
        observation.publish_run_number < 1 ||
        typeof observation.checked_at !== "string" ||
        !Number.isFinite(Date.parse(observation.checked_at)) ||
        typeof observation.ready !== "boolean" ||
        (observation.status !== undefined &&
          (typeof observation.status !== "number" ||
            !Number.isInteger(observation.status) ||
            observation.status < 100 ||
            observation.status > 599)) ||
        (observation.reason !== undefined && typeof observation.reason !== "string")
      )
        throw new TnlError("sdk.response_invalid");
      const observedReadiness = record(observation.readiness, "observed readiness");
      exactKeys(observedReadiness, ["path"], "observed readiness");
      if (typeof observedReadiness.path !== "string") throw new TnlError("sdk.response_invalid");
      if (
        item.ready &&
        (observation.registration_id !== registrationID ||
          observation.publish_run_number !== run ||
          !observation.ready)
      )
        throw new TnlError("sdk.response_invalid");
    } else if (item.ready) throw new TnlError("sdk.response_invalid");
    if (item.registration_id !== registrationID || item.target !== target) return undefined;
    if (item.routable && (!item.registered || publicURL === undefined || run === undefined))
      throw new TnlError("sdk.response_invalid");
    return {
      registered: item.registered as boolean,
      routable: item.routable as boolean,
      ready: item.ready as boolean,
      ...(publicURL === undefined ? {} : { publicURL }),
      ...(run === undefined ? {} : { publishRunNumber: run as number }),
      ...(item.failure === undefined ? {} : { failure: item.failure as string }),
    };
  } catch {
    throw new TnlError("sdk.response_invalid");
  }
}
