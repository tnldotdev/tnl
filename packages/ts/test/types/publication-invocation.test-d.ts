import { publishServer } from "../../src/internal/publisher/publication.js";
import { test } from "vitest";

test("private local invocation selects a publisher file or a stored identity, never both", () => {
  type Options = NonNullable<Parameters<typeof publishServer>[1]>;
  const file: Options = { publisherCredentialFile: "/private/publisher.json" };
  const stored: Options = { publisherIdentityID: `pub_${"A".repeat(22)}` };
  // @ts-expect-error a private invocation still has exactly one identity source.
  const both: Options = {
    publisherCredentialFile: "/private/publisher.json",
    publisherIdentityID: "id",
  };
  void [file, stored, both];
});
