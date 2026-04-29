/// <reference types="vite/client" />

const app = document.querySelector<HTMLDivElement>("#app");

if (app !== null) {
  app.textContent = "Vite fixture";
}

if (import.meta.hot) {
  import.meta.hot.accept();
}
