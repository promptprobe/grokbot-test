import { hmacSha256 } from "../core/crypto.ts";
import {
  base64Decode,
  base64Encode,
  hexDecode,
  timingSafeEqualBytes,
  utf8Encode,
} from "../core/bytes.ts";
import { headerValue, parseUnixSeconds } from "../core/headers.ts";
import type { SignInput, TimestampInfo, VerifyInput, VerifyOutcome } from "../core/types.ts";

export const STANDARD_ID_HEADER = "webhook-id";
export const STANDARD_TIMESTAMP_HEADER = "webhook-timestamp";
export const STANDARD_SIGNATURE_HEADER = "webhook-signature";

export function stripWhsec(secret: string): string {
  return secret.startsWith("whsec_") ? secret.slice("whsec_".length) : secret;
}

export function decodeStandardSecret(secret: string): Uint8Array | null {
  const raw = stripWhsec(secret).trim();
  if (!raw) return null;
  return base64Decode(raw);
}

export function parseStandardSignatures(raw: string): { version: string; value: string }[] {
  const out: { version: string; value: string }[] = [];
  for (const item of raw.trim().split(/\s+/)) {
    if (!item) continue;
    const idx = item.indexOf(",");
    if (idx <= 0) continue;
    out.push({ version: item.slice(0, idx), value: item.slice(idx + 1) });
  }
  return out;
}

export function standardSignedContent(
  id: string,
  timestamp: string | number,
  payload: Uint8Array,
): Uint8Array {
  const prefix = utf8Encode(`${id}.${timestamp}.`);
  const out = new Uint8Array(prefix.length + payload.length);
  out.set(prefix, 0);
  out.set(payload, prefix.length);
  return out;
}

export async function standardSign(input: SignInput): Promise<Record<string, string>> {
  const timestamp = input.timestamp ?? Math.floor(Date.now() / 1000);
  const id = input.id ?? "msg_whyhook_test_0001";
  const key = decodeStandardSecret(input.secret);
  if (!key) {
    throw new Error("Standard Webhooks secret must be base64 (optionally prefixed with whsec_)");
  }
  const mac = await hmacSha256(key, standardSignedContent(id, timestamp, input.payload));
  return {
    [STANDARD_ID_HEADER]: id,
    [STANDARD_TIMESTAMP_HEADER]: String(timestamp),
    [STANDARD_SIGNATURE_HEADER]: `v1,${base64Encode(mac)}`,
  };
}

export async function standardVerify(input: VerifyInput): Promise<VerifyOutcome> {
  const id = headerValue(input.headers, STANDARD_ID_HEADER);
  const tsHeader = headerValue(input.headers, STANDARD_TIMESTAMP_HEADER);
  const sigHeader = headerValue(input.headers, STANDARD_SIGNATURE_HEADER);
  const missing: string[] = [];
  if (!id) missing.push(STANDARD_ID_HEADER);
  if (!tsHeader) missing.push(STANDARD_TIMESTAMP_HEADER);
  if (!sigHeader) missing.push(STANDARD_SIGNATURE_HEADER);
  if (missing.length) {
    return { ok: false, hmacMatch: false, missingHeaders: missing, reason: "missing_header" };
  }
  const timestamp = parseUnixSeconds(tsHeader!);
  if (timestamp === null) {
    return { ok: false, hmacMatch: false, reason: "bad_timestamp" };
  }
  const skewSeconds = Math.abs(input.now - timestamp);
  const withinTolerance = skewSeconds <= input.toleranceSeconds;
  const info: TimestampInfo = {
    value: timestamp,
    skewSeconds,
    withinTolerance,
    toleranceSeconds: input.toleranceSeconds,
  };
  const key = decodeStandardSecret(input.secret);
  if (!key) {
    return { ok: false, hmacMatch: false, timestamp: info, reason: "bad_secret" };
  }
  const expected = await hmacSha256(key, standardSignedContent(id!, tsHeader!, input.payload));
  const signatures = parseStandardSignatures(sigHeader!);
  const v1 = signatures.filter((s) => s.version === "v1");
  if (v1.length === 0) {
    return { ok: false, hmacMatch: false, timestamp: info, reason: "missing_v1" };
  }
  let hmacMatch = false;
  for (const sig of v1) {
    const provided = base64Decode(sig.value) ?? hexDecode(sig.value);
    if (provided && timingSafeEqualBytes(expected, provided)) {
      hmacMatch = true;
      break;
    }
  }
  return {
    ok: hmacMatch && withinTolerance,
    hmacMatch,
    timestamp: info,
    reason: hmacMatch ? (withinTolerance ? undefined : "stale_timestamp") : "bad_signature",
  };
}

export async function standardHmacWithKey(
  key: Uint8Array,
  id: string,
  timestamp: string | number,
  payload: Uint8Array,
): Promise<Uint8Array> {
  return hmacSha256(key, standardSignedContent(id, timestamp, payload));
}
