import { response } from "@tnldotdev/tnl";
import { expectTypeOf, test } from "vitest";

test("the root response helper remains a standard response on native runtimes too", () => {
  expectTypeOf(
    response("body", { headers: [["Set-Cookie", "session=value"]] }),
  ).toEqualTypeOf<Response>();
});
