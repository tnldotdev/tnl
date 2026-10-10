"use client";

import { tnl } from "@tnldotdev/tnl";

export default function Page() {
  return (
    <main>
      <h1>Next.js fixture</h1>
      <p>{`url:${tnl.services?.api?.url}`}</p>
      <p>{`hostname:${tnl.services?.api?.hostname}`}</p>
      <p>{`namespace:${tnl?.namespace}`}</p>
      <p>{`under-dev:${tnl.dev}`}</p>
    </main>
  );
}
