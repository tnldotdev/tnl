import * as core from "@actions/core";
import { main } from "./action.js";
import { ActionError, safeActionMessage } from "./errors.js";

const controller = new AbortController();
const cancel = () => controller.abort();
process.on("SIGINT", cancel);
process.on("SIGTERM", cancel);
try {
  if (process.platform !== "linux") throw new ActionError("TNL_ACTION_PLATFORM_UNSUPPORTED");
  await main({ signal: controller.signal });
} catch (error) {
  core.setFailed(safeActionMessage(error, "TNL_ACTION_SETUP_FAILED"));
} finally {
  process.off("SIGINT", cancel);
  process.off("SIGTERM", cancel);
}
