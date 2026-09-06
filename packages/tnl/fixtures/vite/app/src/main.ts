/// <reference types="vite/client" />

import { tnl } from "@tnldotdev/tnl";

const app = document.querySelector<HTMLDivElement>("#app");

if (app !== null) {
  app.textContent = [
    "Vite fixture",
    `url:${tnl?.services.api?.url}`,
    `hostname:${tnl?.services.api?.hostname}`,
    `namespace:${tnl?.memberNamespace}`,
    `under-dev:${tnl?.runningUnderTnlDev}`,
  ].join(" ");
}

if (import.meta.hot) {
  import.meta.hot.accept();
}
