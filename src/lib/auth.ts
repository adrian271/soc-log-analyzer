import { SignJWT, jwtVerify } from "jose";
import { cookies } from "next/headers";
import { query } from "./db";
import { verifyPassword } from "./password.mjs";

export const SESSION_COOKIE = "soc_session";
const MAX_AGE_SECONDS = 60 * 60 * 8; // one shift

export interface SessionUser {
  id: number;
  email: string;
}

function secret(): Uint8Array {
  const s = process.env.AUTH_SECRET;
  if (!s || s.length < 16) {
    // Failing loudly beats silently signing sessions with a guessable key.
    throw new Error(
      "AUTH_SECRET is missing or too short. Copy .env.example to .env and set it.",
    );
  }
  return new TextEncoder().encode(s);
}

/** Checks credentials against the users table. Returns null on any failure. */
export async function authenticate(
  email: string,
  password: string,
): Promise<SessionUser | null> {
  const rows = await query<{ id: number; email: string; password_hash: string }>(
    "SELECT id, email, password_hash FROM users WHERE email = $1",
    [email.toLowerCase().trim()],
  );
  if (rows.length === 0) return null;
  const ok = await verifyPassword(password, rows[0].password_hash);
  if (!ok) return null;
  return { id: rows[0].id, email: rows[0].email };
}

export async function createSessionToken(user: SessionUser): Promise<string> {
  return new SignJWT({ email: user.email })
    .setProtectedHeader({ alg: "HS256" })
    .setSubject(String(user.id))
    .setIssuedAt()
    .setExpirationTime(`${MAX_AGE_SECONDS}s`)
    .sign(secret());
}

export async function verifySessionToken(
  token: string,
): Promise<SessionUser | null> {
  try {
    const { payload } = await jwtVerify(token, secret());
    const id = Number(payload.sub);
    if (!Number.isFinite(id)) return null;
    return { id, email: String(payload.email ?? "") };
  } catch {
    // Expired, tampered with, or signed by a different secret.
    return null;
  }
}

export async function setSessionCookie(token: string): Promise<void> {
  const store = await cookies();
  store.set(SESSION_COOKIE, token, {
    httpOnly: true, // not readable from JS, so XSS cannot steal the session
    sameSite: "lax", // blocks cross-site form posts riding the cookie
    secure: process.env.NODE_ENV === "production",
    path: "/",
    maxAge: MAX_AGE_SECONDS,
  });
}

export async function clearSessionCookie(): Promise<void> {
  const store = await cookies();
  store.delete(SESSION_COOKIE);
}

/**
 * The authoritative check used by every API route and server page.
 *
 * `src/proxy.ts` also redirects unauthenticated browsers, but that is only a
 * fast path for navigation — authorisation is enforced here, at the point where
 * data is actually read.
 */
export async function currentUser(): Promise<SessionUser | null> {
  const store = await cookies();
  const token = store.get(SESSION_COOKIE)?.value;
  if (!token) return null;
  return verifySessionToken(token);
}

/** Wraps a route handler so it only runs for an authenticated user. */
export async function requireUser(): Promise<SessionUser> {
  const user = await currentUser();
  if (!user) throw new UnauthorizedError();
  return user;
}

export class UnauthorizedError extends Error {
  constructor() {
    super("Not authenticated");
    this.name = "UnauthorizedError";
  }
}
