import { defineConfig } from "vitest/config";
import path from "node:path";

// Next.js loads .env for the app; vitest does not. The evals need the API key
// from the same place the app reads it, so load it here rather than making the
// developer export it by hand. Node 20.12+ builtin — no dotenv dependency.
try {
  process.loadEnvFile(path.resolve(__dirname, ".env"));
} catch {
  // No .env is fine — the eval itself reports a missing key clearly.
}

/**
 * Config for the opt-in evals (`npm run eval:ai`).
 *
 * These are kept out of `npm test` on purpose: they make real API calls, so
 * they cost money, need network, and are non-deterministic. The normal suite
 * has to stay fast and runnable with no credentials.
 */
export default defineConfig({
  resolve: { alias: { "@": path.resolve(__dirname, "src") } },
  test: {
    include: ["evals/**/*.eval.ts"],
    environment: "node",
    // A model pass over ~1,800 events is not a millisecond operation.
    testTimeout: 180_000,
    // One file at a time; these hit a rate-limited API.
    fileParallelism: false,
  },
});
