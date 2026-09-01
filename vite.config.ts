import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// `process` is supplied by the Node.js Vite config runtime. Keeping this
// declaration local avoids adding the full Node type package to the browser app.
declare const process: { env: Record<string, string | undefined> };
const host = process.env.TAURI_DEV_HOST;

export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: {
    port: 1421,
    strictPort: true,
    host: host || false,
    hmr: host
      ? {
          protocol: "ws",
          host,
          port: 1422,
        }
      : undefined,
    watch: {
      ignored: ["**/src-tauri/**"],
    },
  },
});
