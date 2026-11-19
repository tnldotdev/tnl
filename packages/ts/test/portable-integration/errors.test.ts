import { expect, test, vi } from "vitest";
import { PortableSmokeError, portableDiagnostics } from "./errors.ts";
import { FixtureAssertionError } from "./fixture.ts";

test("connector diagnostics expose cleanup error kinds without private messages", () => {
  const privateMessage = "private request and database credential";
  const error = new PortableSmokeError(
    "close-deployment",
    new AggregateError(
      [
        Object.assign(new Error(privateMessage), { code: "sdk.cleanup_failed" }),
        new TypeError(privateMessage),
        new Error(privateMessage),
      ],
      privateMessage,
    ),
  );
  expect(error).toMatchObject({
    phase: "close-deployment",
    code: "fixture.operation_failed",
    detail: "sdk.cleanup_failed, TypeError, unknown_error",
  });
  expect(JSON.stringify(error)).not.toContain(privateMessage);
});

test("connector diagnostics keep fixture assertions and bound nested failures", () => {
  expect(
    new PortableSmokeError("close-read", new FixtureAssertionError("blocked read returned bytes")),
  ).toMatchObject({ detail: "blocked read returned bytes" });
  const nested = new AggregateError(
    Array.from({ length: 100 }, () => new AggregateError([new TypeError("private")], "private")),
    "private",
  );
  expect(new PortableSmokeError("cleanup", nested).detail).toBe(
    Array.from({ length: 8 }, () => "TypeError").join(", "),
  );
  expect(
    new PortableSmokeError(
      "cleanup",
      new AggregateError([new AggregateError([new AggregateError([nested])])]),
    ).detail,
  ).toBe("nested_error");
});

test("connector Go diagnostics expose fixed facts and strip unknown fields", () => {
  const diagnostic = {
    types: ["*errors.joinError", "*stream.CleanupError"],
    resets: [{ remote: true, code: 7 }],
    canceled: true,
    deadline: false,
    closed: false,
    pipe_closed: false,
    eof: false,
    terminal_failed: true,
    service_unavailable: false,
  };
  vi.stubGlobal("__tnlWasmFixtureDiagnostics", [
    { ...diagnostic, message: "private fixture credential" },
  ]);
  expect(portableDiagnostics()).toEqual([diagnostic]);
  vi.stubGlobal("__tnlWasmFixtureDiagnostics", [
    { ...diagnostic, types: ["private credential with spaces"] },
  ]);
  expect(portableDiagnostics()).toBeUndefined();
  vi.unstubAllGlobals();
});
