import { render } from "preact";
import { createFeedbackAPI } from "./api.ts";
import { Toolbar } from "./toolbar.tsx";
import styles from "./toolbar.css";

// a repeated script injection must not duplicate the toolbar or page listeners.
if (!document.querySelector("[data-tnl-feedback]")) {
  const host = document.createElement("div");
  host.setAttribute("data-tnl-feedback", "");
  const root = host.attachShadow({ mode: "open" });
  if ("FontFace" in window) {
    const font = new FontFace("tnl Fira Code", "url('/__tnl/feedback/fira-code.woff2')", {
      weight: "300 700",
    });
    void font
      .load()
      .then((loaded) => {
        document.fonts.add(loaded);
      })
      .catch(() => {
        /* the monospace fallback also works under restrictive font-src */
      });
  }
  const style = document.createElement("style");
  style.nonce =
    document.querySelector<HTMLScriptElement>('script[src^="/__tnl/feedback/toolbar."]')?.nonce ??
    "";
  style.textContent = styles;
  const content = document.createElement("div");
  root.append(style, content);
  document.documentElement.append(host);
  render(<Toolbar api={createFeedbackAPI()} document={document} host={host} />, content);
}
