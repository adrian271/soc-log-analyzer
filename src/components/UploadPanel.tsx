"use client";

import { useRef, useState } from "react";
import { useRouter } from "next/navigation";

/** Drag-and-drop / click-to-browse upload, posting to POST /api/uploads. */
export function UploadPanel() {
  const router = useRouter();
  const inputRef = useRef<HTMLInputElement>(null);
  const [dragging, setDragging] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function upload(file: File) {
    setBusy(true);
    setError(null);

    const body = new FormData();
    body.append("file", file);

    try {
      const res = await fetch("/api/uploads", { method: "POST", body });
      const payload = await res.json().catch(() => ({}));

      if (!res.ok) {
        setError(payload.error ?? `Upload failed (${res.status})`);
        return;
      }
      router.push(`/uploads/${payload.uploadId}`);
    } catch {
      setError("Could not reach the server");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <div
        onDragOver={(e) => {
          e.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDragging(false);
          const file = e.dataTransfer.files?.[0];
          if (file) void upload(file);
        }}
        onClick={() => inputRef.current?.click()}
        role="button"
        tabIndex={0}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") inputRef.current?.click();
        }}
        aria-label="Upload a log file"
        className="card p-8 text-center cursor-pointer transition-colors"
        style={
          dragging
            ? {
                borderColor: "var(--series-1)",
                background: "color-mix(in srgb, var(--series-1) 6%, transparent)",
              }
            : undefined
        }
      >
        <input
          ref={inputRef}
          type="file"
          accept=".log,.txt,.tsv,.csv"
          className="hidden"
          onChange={(e) => {
            const file = e.target.files?.[0];
            if (file) void upload(file);
            e.target.value = "";
          }}
        />

        {busy ? (
          <p className="text-sm text-[var(--text-secondary)]">
            Parsing and analysing…
          </p>
        ) : (
          <>
            <p className="text-sm font-medium">
              Drop a log file here, or click to browse
            </p>
            <p className="mt-1 text-xs text-[var(--text-muted)]">
              ZScaler web proxy format · .log .txt .tsv .csv · up to 4 MB
            </p>
          </>
        )}
      </div>

      {error && (
        <p role="alert" className="mt-3 text-sm text-[var(--status-critical)]">
          ⚠ {error}
        </p>
      )}
    </div>
  );
}
