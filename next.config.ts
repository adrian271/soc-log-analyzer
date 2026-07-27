import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  /**
   * `/api/examples/[name]` reads the sample logs off disk at request time.
   *
   * Next only bundles files it can trace through imports, and a path built with
   * `path.join(process.cwd(), …)` is invisible to that analysis — so without
   * this the route works locally and 500s on Vercel, which is the worst
   * possible failure mode. Naming the folder explicitly puts it in the bundle.
   */
  outputFileTracingIncludes: {
    "/api/examples/[name]": ["./examples/**/*.log"],
  },
};

export default nextConfig;
