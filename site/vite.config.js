import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// The site is published as a GitHub Pages project page:
// https://devanimecx.github.io/redfall/
export default defineConfig({
  base: "/redfall/",
  plugins: [react(), tailwindcss()],
  build: {
    target: "es2020",
    cssMinify: "lightningcss",
  },
});
