import { fixtureSchema } from "./fixture.ts";
import { installFixtureHost } from "./host.ts";
import { runPortableIsolation, runPortableSmoke } from "./smoke.ts";
import { PortableSmokeError } from "./errors.ts";

function failure(error: unknown): { phase: string; code: string; detail?: string | undefined }[] {
  const errors = error instanceof AggregateError ? error.errors : [error];
  return errors.flatMap((value: unknown) =>
    value instanceof AggregateError
      ? failure(value)
      : value instanceof PortableSmokeError
        ? [{ phase: value.phase, code: value.code, detail: value.detail }]
        : [{ phase: "fixture", code: "fixture.operation_failed" }],
  );
}

export async function smoke(input: unknown) {
  const fixture = fixtureSchema.parse(input);
  installFixtureHost(fixture);
  try {
    return await runPortableSmoke(fixture);
  } catch (error) {
    throw new Error(JSON.stringify(failure(error)));
  }
}

export async function isolation(input: unknown, role: "first" | "second", run: string) {
  const fixture = fixtureSchema.parse(input);
  installFixtureHost(fixture);
  try {
    return await runPortableIsolation(fixture, role, run);
  } catch (error) {
    throw new Error(JSON.stringify(failure(error)));
  }
}
