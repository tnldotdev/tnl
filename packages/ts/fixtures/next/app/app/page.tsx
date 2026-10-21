"use client";

import { tnl } from "@tnldotdev/tnl";

export default function Page() {
  const metadata = tnl.services.api;
  return (
    <main>
      <h1>Next.js fixture</h1>
      <p>{`url:${metadata?.protocol === "http" ? metadata.url : undefined}`}</p>
      <p>{`hostname:${metadata?.hostname}`}</p>
      <p>{`namespace:${tnl?.namespace}`}</p>
      <p>{`under-dev:${tnl.dev}`}</p>
    </main>
  );
}
