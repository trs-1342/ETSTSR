import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    host: "192.168.1.100", // "0.0.0.0",
    port: 1342, // 80,
    strictPort: true,
    cors: {
      origin: ["http://192.168.1.100", "http://192.168.1.100"],
      credentials: true,
    },
    headers: {
      "Access-Control-Allow-Origin": "http://192.168.1.100",
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
