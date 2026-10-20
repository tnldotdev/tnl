/// <reference types="vite/client" />

import { tnl } from "@tnldotdev/tnl";

const app = document.querySelector<HTMLDivElement>("#app");

if (app !== null) {
  const metadata = tnl.services.api?.metadata;
  app.textContent = [
    "Vite fixture",
    `url:${metadata?.protocol === "http" ? metadata.url : undefined}`,
    `hostname:${metadata?.hostname}`,
    `namespace:${tnl?.namespace}`,
    `under-dev:${tnl.dev}`,
  ].join(" ");
}

if (import.meta.hot) {
  import.meta.hot.accept();
}
