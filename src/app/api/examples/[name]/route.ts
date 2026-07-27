import { readFile } from "node:fs/promises";
import path from "node:path";
import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import { currentUser } from "@/lib/auth";

/**
 * Serves the bundled example logs so someone using the deployed app has
 * something to upload without cloning the repository.
 *
 * `pg` isn't involved but the auth check is, so this stays on the Node runtime.
 */
export const runtime = "nodejs";

/**
 * An allow-list, not a sanitiser.
 *
 * The filename comes from the URL, and `examples/` sits next to `.env` and the
 * rest of the project. Validating a user-supplied path — stripping `..`,
 * resolving symlinks, checking prefixes — is a category of bug that keeps being
 * rediscovered. Mapping a fixed set of keys to a fixed set of files means there
 * is no path to traverse: anything not in this object is a 404 before the
 * filesystem is touched.
 */
const EXAMPLES = {
  "zscaler-sample.log": {
    file: "zscaler-sample.log",
    description: "Benign corporate traffic with seven attack scenarios seeded in",
  },
  "zscaler-benign.log": {
    file: "zscaler-benign.log",
    description: "Normal traffic only — should produce zero findings",
  },
} as const;

type ExampleName = keyof typeof EXAMPLES;

function isExample(name: string): name is ExampleName {
  return Object.hasOwn(EXAMPLES, name);
}

export async function GET(
  _request: NextRequest,
  context: RouteContext<"/api/examples/[name]">,
) {
  const user = await currentUser();
  if (!user) {
    return NextResponse.json({ error: "Not authenticated" }, { status: 401 });
  }

  const { name } = await context.params;
  if (!isExample(name)) {
    return NextResponse.json({ error: "Unknown example" }, { status: 404 });
  }

  // Resolved from the project root, not from the request.
  const filePath = path.join(process.cwd(), "examples", EXAMPLES[name].file);

  let contents: string;
  try {
    contents = await readFile(filePath, "utf8");
  } catch {
    // In a serverless deployment this means the file wasn't traced into the
    // bundle — see outputFileTracingIncludes in next.config.ts.
    console.error(`[examples] could not read ${filePath}`);
    return NextResponse.json(
      { error: "Example file is unavailable in this deployment" },
      { status: 500 },
    );
  }

  return new NextResponse(contents, {
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      "Content-Disposition": `attachment; filename="${EXAMPLES[name].file}"`,
      // These change only when the logs are regenerated.
      "Cache-Control": "private, max-age=3600",
    },
  });
}
