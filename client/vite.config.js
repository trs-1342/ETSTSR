import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    host: "0.0.0.0",
    port: 80,
    strictPort: true,
    cors: {
      origin: ["http://192.168.0.201", "http://192.168.0.201"],
      credentials: true,
    },
    headers: {
      "Access-Control-Allow-Origin": "http://192.168.0.201",
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
