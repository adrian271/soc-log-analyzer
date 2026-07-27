"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";

export function AppHeader({ email }: { email: string }) {
  const router = useRouter();

  async function signOut() {
    await fetch("/api/auth/logout", { method: "POST" });
    router.replace("/login");
    router.refresh();
  }

  return (
    <header className="border-b border-[var(--border)] bg-[var(--surface)]">
      <div className="mx-auto max-w-6xl px-4 py-3 flex items-center justify-between gap-4">
        <Link href="/" className="font-semibold tracking-tight">
          SOC Log Analyzer
        </Link>
        <div className="flex items-center gap-3 text-xs text-[var(--text-secondary)]">
          <span className="hidden sm:inline">{email}</span>
          <button
            type="button"
            onClick={signOut}
            className="rounded-md border border-[var(--border)] px-2.5 py-1 hover:bg-[var(--surface-2)]"
          >
            Sign out
          </button>
        </div>
      </div>
    </header>
  );
}
