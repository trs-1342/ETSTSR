import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    host: "localhost", // "0.0.0.0",
    port: 1342, // 80,
    strictPort: true,
    cors: {
      origin: ["http://localhost", "http://localhost"],
      credentials: true,
    },
    headers: {
      "Access-Control-Allow-Origin": "http://localhost",
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
