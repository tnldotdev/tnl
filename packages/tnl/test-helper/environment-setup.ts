import { beforeEach, vi } from "vitest";
import { environmentBaseline } from "./environment.js";

beforeEach(() => {
  for (const [name, value] of Object.entries(environmentBaseline)) vi.stubEnv(name, value);
});
