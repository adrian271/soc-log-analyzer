"use client";

import { Suspense, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";

/**
 * `useSearchParams` suspends during prerender, so the form lives inside a
 * Suspense boundary rather than at the page root.
 */
export default function LoginPage() {
  return (
    <Suspense fallback={null}>
      <LoginForm />
    </Suspense>
  );
}

function LoginForm() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);

    try {
      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });

      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        setError(body.error ?? "Sign in failed");
        return;
      }

      // Full navigation so the proxy re-reads the freshly-set session cookie.
      router.replace(searchParams.get("next") ?? "/");
      router.refresh();
    } catch {
      setError("Could not reach the server");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="flex-1 grid place-items-center px-4 py-12">
      <div className="w-full max-w-sm">
        <div className="mb-8">
          <h1 className="text-2xl font-semibold tracking-tight">
            SOC Log Analyzer
          </h1>
          <p className="mt-1 text-sm text-[var(--text-secondary)]">
            Sign in to upload and triage proxy logs.
          </p>
        </div>

        <form onSubmit={onSubmit} className="card p-6 space-y-4">
          <div>
            <label
              htmlFor="email"
              className="block text-xs font-medium text-[var(--text-secondary)] mb-1.5"
            >
              Email
            </label>
            <input
              id="email"
              type="email"
              required
              autoComplete="username"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full rounded-md border border-[var(--border)] bg-[var(--surface-2)] px-3 py-2 text-sm outline-none focus:border-[var(--series-1)]"
            />
          </div>

          <div>
            <label
              htmlFor="password"
              className="block text-xs font-medium text-[var(--text-secondary)] mb-1.5"
            >
              Password
            </label>
            <input
              id="password"
              type="password"
              required
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full rounded-md border border-[var(--border)] bg-[var(--surface-2)] px-3 py-2 text-sm outline-none focus:border-[var(--series-1)]"
            />
          </div>

          {error && (
            <p
              role="alert"
              className="text-sm text-[var(--status-critical)] flex items-start gap-1.5"
            >
              <span aria-hidden>⚠</span>
              <span>{error}</span>
            </p>
          )}

          <button
            type="submit"
            disabled={busy}
            className="w-full rounded-md bg-[var(--series-1)] px-3 py-2 text-sm font-medium text-white disabled:opacity-60"
          >
            {busy ? "Signing in…" : "Sign in"}
          </button>
        </form>

        {/*
          No credentials printed here. This is a publicly reachable deployment
          and every upload costs two model calls, so the sign-in details are
          shared directly with reviewers rather than published on the page.
          Local setup instructions are in the README.
        */}
      </div>
    </main>
  );
}
