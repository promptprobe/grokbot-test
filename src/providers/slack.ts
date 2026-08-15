import { hmacSha256 } from "../core/crypto.ts";
import {
  hexEncode,
  timingSafeEqualBytes,
  utf8Encode,
} from "../core/bytes.ts";
import { headerValue, parseUnixSeconds } from "../core/headers.ts";
import type { SignInput, TimestampInfo, VerifyInput, VerifyOutcome } from "../core/types.ts";

export const SLACK_SIGNATURE_HEADER = "X-Slack-Signature";
export const SLACK_TIMESTAMP_HEADER = "X-Slack-Request-Timestamp";

export function parseSlackSignature(raw: string): { prefix: string | null; hex: string | null } {
  const value = raw.trim();
  const match = /^(v0=)([0-9a-fA-F]+)$/.exec(value);
  if (match) return { prefix: "v0=", hex: match[2]! };
  if (/^[0-9a-fA-F]+$/.test(value) && value.length % 2 === 0) {
    return { prefix: null, hex: value };
  }
  return { prefix: null, hex: null };
}

export function slackSignedPayload(timestamp: number | string, payload: Uint8Array): Uint8Array {
  const prefix = utf8Encode(`v0:${timestamp}:`);
  const out = new Uint8Array(prefix.length + payload.length);
  out.set(prefix, 0);
  out.set(payload, prefix.length);
  return out;
}

export function slackSignedPayloadNoV0(
  timestamp: number | string,
  payload: Uint8Array,
): Uint8Array {
  const prefix = utf8Encode(`${timestamp}:`);
  const out = new Uint8Array(prefix.length + payload.length);
  out.set(prefix, 0);
  out.set(payload, prefix.length);
  return out;
}

export async function slackSign(input: SignInput): Promise<Record<string, string>> {
  const timestamp = input.timestamp ?? Math.floor(Date.now() / 1000);
  const mac = await hmacSha256(input.secret, slackSignedPayload(timestamp, input.payload));
  return {
    [SLACK_TIMESTAMP_HEADER]: String(timestamp),
    [SLACK_SIGNATURE_HEADER]: `v0=${hexEncode(mac)}`,
  };
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

export async function slackVerify(input: VerifyInput): Promise<VerifyOutcome> {
  const sigHeader = headerValue(input.headers, SLACK_SIGNATURE_HEADER);
  const tsHeader = headerValue(input.headers, SLACK_TIMESTAMP_HEADER);
  const missing: string[] = [];
  if (!sigHeader) missing.push(SLACK_SIGNATURE_HEADER);
  if (!tsHeader) missing.push(SLACK_TIMESTAMP_HEADER);
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
  const parsed = parseSlackSignature(sigHeader!);
  if (!parsed.hex) {
    return { ok: false, hmacMatch: false, timestamp: info, reason: "bad_signature" };
  }
  const provided = hexToBytes(parsed.hex);
  if (!provided) {
    return { ok: false, hmacMatch: false, timestamp: info, reason: "bad_signature" };
  }
  const expected = await hmacSha256(
    input.secret,
    slackSignedPayload(tsHeader!, input.payload),
  );
  const bytesMatch = timingSafeEqualBytes(expected, provided);
  const hmacMatch = bytesMatch && parsed.prefix === "v0=";
  return {
    ok: hmacMatch && withinTolerance,
    hmacMatch,
    timestamp: info,
    reason: hmacMatch ? (withinTolerance ? undefined : "stale_timestamp") : "bad_signature",
  };
}

export async function slackHmac(
  secret: string,
  timestamp: string | number,
  payload: Uint8Array,
  includeV0Prefix: boolean,
): Promise<Uint8Array> {
  const data = includeV0Prefix
    ? slackSignedPayload(timestamp, payload)
    : slackSignedPayloadNoV0(timestamp, payload);
  return hmacSha256(secret, data);
}
