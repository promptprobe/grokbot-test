import { defineConfig } from "vite";
import path from "node:path";

export default defineConfig({
  root: "src/web",
  build: {
    outDir: path.resolve("dist/web"),
    emptyOutDir: true,
    sourcemap: true,
  },
  server: {
    host: "127.0.0.1",
    port: 8787,
    strictPort: true,
  },
  preview: {
    host: "127.0.0.1",
    port: 8787,
  },
});
