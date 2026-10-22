import * as core from "@actions/core";
import { post } from "./action.js";
import { safeActionMessage } from "./errors.js";

try {
  await post();
} catch (error) {
  core.setFailed(safeActionMessage(error, "TNL_ACTION_CLEANUP_FAILED"));
}
