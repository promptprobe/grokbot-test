import { sha256Hex } from "./crypto.ts";
import type { SecretHint } from "./types.ts";

export function normalizeHeaders(
  headers: Record<string, string>,
): Map<string, { name: string; value: string }> {
  const map = new Map<string, { name: string; value: string }>();
  for (const [rawName, rawValue] of Object.entries(headers)) {
    const name = rawName.trim();
    if (!name) continue;
    map.set(name.toLowerCase(), { name, value: String(rawValue).trim() });
  }
  return map;
}

export function headerValue(
  headers: Record<string, string>,
  canonicalName: string,
): string | undefined {
  return normalizeHeaders(headers).get(canonicalName.toLowerCase())?.value;
}

export function parseHeaderLines(text: string): Record<string, string> {
  const trimmed = text.trim();
  if (!trimmed) return {};
  if (trimmed.startsWith("{")) {
    const parsed: unknown = JSON.parse(trimmed);
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error("headers JSON must be an object of name → value strings");
    }
    const out: Record<string, string> = {};
    for (const [k, v] of Object.entries(parsed as Record<string, unknown>)) {
      if (typeof v !== "string") {
        throw new Error(`header "${k}" must be a string`);
      }
      out[k] = v;
    }
    return out;
  }
  const out: Record<string, string> = {};
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    if (!line.trim() || line.trimStart().startsWith("#")) continue;
    const idx = line.indexOf(":");
    if (idx <= 0) {
      throw new Error(`invalid header line ${i + 1}: expected "Name: value"`);
    }
    const name = line.slice(0, idx).trim();
    const value = line.slice(idx + 1).trim();
    out[name] = value;
  }
  return out;
}

export function parseSingleHeader(raw: string): { name: string; value: string } {
  const idx = raw.indexOf(":");
  if (idx <= 0) {
    throw new Error(`invalid --header value: expected "Name: value", got ${JSON.stringify(raw)}`);
  }
  return { name: raw.slice(0, idx).trim(), value: raw.slice(idx + 1).trim() };
}

export async function secretHint(secret: string): Promise<SecretHint> {
  const digest = await sha256Hex(secret);
  return {
    provided: true,
    length: secret.length,
    fingerprint: digest.slice(0, 8),
  };
}

export function unixNowSeconds(now?: number): number {
  if (typeof now === "number" && Number.isFinite(now)) return Math.floor(now);
  return Math.floor(Date.now() / 1000);
}

export function parseUnixSeconds(value: string): number | null {
  if (!/^-?\d+$/.test(value.trim())) return null;
  const n = Number.parseInt(value.trim(), 10);
  if (!Number.isFinite(n)) return null;
  return n;
}

export function parseNonNegativeInt(value: string): number | null {
  if (!/^\d+$/.test(value)) return null;
  const n = Number.parseInt(value, 10);
  if (!Number.isFinite(n) || n < 0) return null;
  return n;
}
