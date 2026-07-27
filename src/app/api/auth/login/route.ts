import { NextResponse } from "next/server";
import { authenticate, createSessionToken, setSessionCookie } from "@/lib/auth";

export async function POST(request: Request) {
  let body: { email?: string; password?: string };
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }

  const { email, password } = body;
  if (!email || !password) {
    return NextResponse.json(
      { error: "Email and password are required" },
      { status: 400 },
    );
  }

  const user = await authenticate(email, password);
  if (!user) {
    // Deliberately identical response for unknown user and wrong password, so
    // the endpoint can't be used to enumerate valid accounts.
    return NextResponse.json(
      { error: "Invalid email or password" },
      { status: 401 },
    );
  }

  await setSessionCookie(await createSessionToken(user));
  return NextResponse.json({ user });
}
