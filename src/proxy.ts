import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import { SESSION_COOKIE, verifySessionToken } from "@/lib/auth";

/**
 * Next.js 16 renamed Middleware to Proxy; this file is the same concept.
 *
 * This is an *optimistic* check only: it redirects browsers that clearly have
 * no valid session so they don't flash an empty dashboard. It is NOT the
 * authorisation boundary — every API route and page independently calls
 * `currentUser()` and scopes its queries by user id. Treating the proxy as the
 * only gate would be a mistake, since it never touches the database and can't
 * tell whether the user still exists.
 */
export async function proxy(request: NextRequest) {
  const { pathname } = request.nextUrl;
  const token = request.cookies.get(SESSION_COOKIE)?.value;
  const session = token ? await verifySessionToken(token) : null;

  // Signed-in users have no reason to see the login page.
  if (pathname === "/login" && session) {
    return NextResponse.redirect(new URL("/", request.url));
  }

  if (pathname !== "/login" && !session) {
    const url = new URL("/login", request.url);
    // Preserve where they were heading so login can bounce them back.
    if (pathname !== "/") url.searchParams.set("next", pathname);
    return NextResponse.redirect(url);
  }

  return NextResponse.next();
}

export const config = {
  // Page routes only. API routes enforce auth themselves and must return 401
  // JSON rather than a redirect to an HTML page.
  matcher: ["/((?!api|_next/static|_next/image|favicon.ico|.*\\.svg).*)"],
};
