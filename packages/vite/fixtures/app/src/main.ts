/// <reference types="vite/client" />

const app = document.querySelector<HTMLDivElement>("#app");

if (app !== null) {
  app.textContent = [
    "Vite fixture",
    `url:${import.meta.env.VITE_TNL_URL}`,
    `hostname:${import.meta.env.VITE_TNL_HOSTNAME}`,
    `tunnel-id:${import.meta.env.VITE_TNL_TUNNEL_ID}`,
  ].join(" ");
}

if (import.meta.hot) {
  import.meta.hot.accept();
}
