import * as z from "zod";
import { TnlCleanupError, TnlError, safeTnlMessage } from "../../errors.js";
import { serializeRuntimePayload } from "../project/runtime.js";
import { parseValue } from "../validation.js";
import {
  prepareOptionsSchema,
  prepareService,
  reportFrameworkTarget,
  type PreparedService,
} from "./app.js";

const previewSchema = z.union([z.literal(false), z.enum(["auto", "required"])]);
const frameworkOptionsSchema = prepareOptionsSchema
  .extend({
    preview: previewSchema.exactOptional(),
  })
  .readonly();

export type FrameworkOptions = z.output<typeof frameworkOptionsSchema>;
type PreviewMode = z.output<typeof previewSchema>;
export const localRuntimePayload = serializeRuntimePayload({ namespace: "", services: {} }, true);

export function frameworkOptions(options: FrameworkOptions): {
  preview: PreviewMode;
  preparation: z.output<typeof prepareOptionsSchema>;
} {
  const { preview = "auto", ...preparation } = parseValue(
    frameworkOptionsSchema,
    options,
    "sdk.configuration_invalid",
  );
  const override = process.env.TNL_PREVIEW;
  return {
    preview:
      override === undefined
        ? preview
        : parseValue(
            previewSchema,
            override === "off" ? false : override,
            "sdk.configuration_invalid",
          ),
    preparation,
  };
}

// only expected preview availability failures are optional. invalid configuration,
// protocol mismatches, and programming errors must remain visible.
export async function frameworkOperation<T>(
  preview: PreviewMode,
  operation: (signal?: AbortSignal) => Promise<T>,
): Promise<T | null> {
  if (preview === false) return null;
  const controller = new AbortController();
  const timer =
    preview === "auto"
      ? setTimeout(() => controller.abort(new TnlError("sdk.dev_unavailable")), 3_000)
      : undefined;
  try {
    return await operation(preview === "auto" ? controller.signal : undefined);
  } catch (error) {
    if (
      preview !== "auto" ||
      !(error instanceof TnlError) ||
      ![
        "sdk.authentication_required",
        "sdk.publisher_setup_required",
        "sdk.dev_unavailable",
        "sdk.registration_stale",
        "sdk.owner_conflict",
        "sdk.native_missing",
        "sdk.native_unsupported",
        "sdk.process_unavailable",
      ].includes(error.code)
    )
      throw error;
    process.stderr.write(
      `tnl: preview unavailable [${error.code}]; continuing local development. ${safeTnlMessage(error)}\n`,
    );
    return null;
  } finally {
    clearTimeout(timer);
  }
}

export async function prepareFramework(
  options: FrameworkOptions,
  framework: "vite" | "next",
  target?: `http://${string}`,
): Promise<PreparedService | null> {
  const { preview, preparation } = frameworkOptions(options);
  return frameworkOperation(preview, async (signal) => {
    const prepared = await prepareService(preparation, framework, signal);
    try {
      if (target !== undefined) await reportFrameworkTarget(prepared, target, signal);
      return prepared;
    } catch (error) {
      await closeFramework(prepared, error);
      throw error;
    }
  });
}

export async function closeFramework(prepared: PreparedService, error: unknown): Promise<void> {
  try {
    await prepared.close(AbortSignal.timeout(3_000));
  } catch (cleanupError) {
    throw new TnlCleanupError(error, cleanupError);
  }
}
