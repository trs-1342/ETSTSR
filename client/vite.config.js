import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    host: "0.0.0.0",
    port: 80,
    strictPort: true,
    cors: {
      origin: ["http://78.188.217.104", "http://78.188.217.104"],
      credentials: true,
    },
    headers: {
      "Access-Control-Allow-Origin": "http://78.188.217.104",
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
