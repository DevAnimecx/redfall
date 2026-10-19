import { StrictMode } from "react";
import { hydrateRoot } from "react-dom/client";
import App from "./App.jsx";
import "./index.css";

// The page is prerendered, so the markup is already on screen and the fonts
// are already requested. Hydration can wait for the first idle slot: doing it
// synchronously in the initial task delays text paint behind 76 kB of JS.
function hydrate() {
  hydrateRoot(
    document.getElementById("root"),
    <StrictMode>
      <App />
    </StrictMode>,
  );
}

if ("requestIdleCallback" in window) {
  requestIdleCallback(hydrate, { timeout: 1500 });
} else {
  window.addEventListener("load", () => window.setTimeout(hydrate, 0), { once: true });
}
