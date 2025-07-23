import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    host: "127.0.0.1", // "0.0.0.0",
    port: 1342, // 80,
    strictPort: true,
    cors: {
      origin: ["http://127.0.0.1", "http://127.0.0.1"],
      credentials: true,
    },
    headers: {
      "Access-Control-Allow-Origin": "http://127.0.0.1",
      "Access-Control-Allow-Credentials": "true",
    },
    watch: {
      usePolling: true,
    },
  },
  resolve: {
    alias: {
      "@": "/src",
    },
  },
  build: {
    target: "esnext",
  },
});
