import { spawnSync } from "node:child_process";
import { expect, test } from "vitest";
import { z } from "zod";
import { ToolError, safeToolMessage, toolFailure } from "./errors.ts";
import { parseJSON, parseValue } from "./validation.ts";

test("validation preserves syntax and schema causes without reporting input", () => {
  let syntax: unknown;
  try {
    parseJSON("private-test-secret", z.object({}), "input");
  } catch (error) {
    syntax = error;
  }
  expect(syntax).toMatchObject({ code: "tool.input_invalid", cause: expect.any(SyntaxError) });
  let shape: unknown;
  try {
    parseValue(
      { secret: "private-test-secret" },
      z.object({ secret: z.literal("expected") }),
      "input",
    );
  } catch (error) {
    shape = error;
  }
  expect(shape).toMatchObject({ code: "tool.input_invalid", cause: expect.any(z.ZodError) });
  expect(safeToolMessage(shape)).not.toContain("private-test-secret");
  const cause = new Error("private-test-secret");
  expect(toolFailure(cause, "tool.process_failed").cause).toBe(cause);
  expect(toolFailure(new ToolError("tool.interrupted"))).toMatchObject({ retry: "never" });
});

test("entrypoint preflight failures report one authored line before work starts", () => {
  const result = spawnSync(
    process.execPath,
    [new URL("./normalize-openapi-go.ts", import.meta.url).pathname],
    { encoding: "utf8" },
  );
  expect(result.status).toBe(1);
  expect(result.stdout).toBe("");
  expect(result.stderr).toMatch(
    /^tnl tooling: normalize-openapi-go.ts: tool.input_invalid: [^\n]+\n$/,
  );
  expect(result.stderr).not.toContain("at ");
});
