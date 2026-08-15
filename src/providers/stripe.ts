import { hmacSha256 } from "../core/crypto.ts";
import {
  hexEncode,
  timingSafeEqualBytes,
  utf8Encode,
} from "../core/bytes.ts";
import { headerValue, parseUnixSeconds } from "../core/headers.ts";
import type { SignInput, TimestampInfo, VerifyInput, VerifyOutcome } from "../core/types.ts";

export const STRIPE_SIGNATURE_HEADER = "Stripe-Signature";

export interface StripeSigParts {
  timestamp: number | null;
  v1: string[];
  v0: string[];
  raw: string;
}

export function parseStripeSignature(raw: string): StripeSigParts {
  const parts: StripeSigParts = { timestamp: null, v1: [], v0: [], raw };
  for (const item of raw.split(",")) {
    const idx = item.indexOf("=");
    if (idx <= 0) continue;
    const key = item.slice(0, idx).trim();
    const value = item.slice(idx + 1).trim();
    if (key === "t") {
      parts.timestamp = parseUnixSeconds(value);
    } else if (key === "v1") {
      parts.v1.push(value);
    } else if (key === "v0") {
      parts.v0.push(value);
    }
  }
  return parts;
}

function hexToBytes(hex: string): Uint8Array | null {
  const clean = hex.trim().toLowerCase();
  if (clean.length % 2 !== 0 || !/^[0-9a-f]+$/.test(clean)) return null;
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function stripeSignedPayload(timestamp: number, payload: Uint8Array): Uint8Array {
  const prefix = utf8Encode(`${timestamp}.`);
  const out = new Uint8Array(prefix.length + payload.length);
  out.set(prefix, 0);
  out.set(payload, prefix.length);
  return out;
}

export async function stripeSign(input: SignInput): Promise<Record<string, string>> {
  const timestamp = input.timestamp ?? Math.floor(Date.now() / 1000);
  const mac = await hmacSha256(input.secret, stripeSignedPayload(timestamp, input.payload));
  return {
    [STRIPE_SIGNATURE_HEADER]: `t=${timestamp},v1=${hexEncode(mac)}`,
  };
}

export async function stripeVerify(input: VerifyInput): Promise<VerifyOutcome> {
  const header = headerValue(input.headers, STRIPE_SIGNATURE_HEADER);
  if (!header) {
    return {
      ok: false,
      hmacMatch: false,
      missingHeaders: [STRIPE_SIGNATURE_HEADER],
      reason: "missing_header",
    };
  }
  const parsed = parseStripeSignature(header);
  if (parsed.timestamp === null) {
    return { ok: false, hmacMatch: false, reason: "missing_timestamp" };
  }
  if (parsed.v1.length === 0) {
    return { ok: false, hmacMatch: false, reason: "missing_v1" };
  }
  const skewSeconds = Math.abs(input.now - parsed.timestamp);
  const withinTolerance = skewSeconds <= input.toleranceSeconds;
  const timestamp: TimestampInfo = {
    value: parsed.timestamp,
    skewSeconds,
    withinTolerance,
    toleranceSeconds: input.toleranceSeconds,
  };
  const expected = await hmacSha256(
    input.secret,
    stripeSignedPayload(parsed.timestamp, input.payload),
  );
  let hmacMatch = false;
  for (const v1 of parsed.v1) {
    const provided = hexToBytes(v1);
    if (provided && timingSafeEqualBytes(expected, provided)) {
      hmacMatch = true;
      break;
    }
  }
  return {
    ok: hmacMatch && withinTolerance,
    hmacMatch,
    timestamp,
    reason: hmacMatch ? (withinTolerance ? undefined : "stale_timestamp") : "bad_signature",
  };
}

export async function stripeHmacRawBody(secret: string, payload: Uint8Array): Promise<Uint8Array> {
  return hmacSha256(secret, payload);
}

export async function stripeHmacSigned(
  secret: string,
  timestamp: number,
  payload: Uint8Array,
): Promise<Uint8Array> {
  return hmacSha256(secret, stripeSignedPayload(timestamp, payload));
}
