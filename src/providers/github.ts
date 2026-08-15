import { hmacSha256 } from "../core/crypto.ts";
import {
  hexEncode,
  timingSafeEqualBytes,
  utf8Encode,
} from "../core/bytes.ts";
import { headerValue } from "../core/headers.ts";
import type { SignInput, VerifyInput, VerifyOutcome } from "../core/types.ts";

export const GITHUB_SIGNATURE_HEADER = "X-Hub-Signature-256";

export function parseGithubSignature(raw: string): {
  prefix: string | null;
  hex: string | null;
  rest: string;
} {
  const value = raw.trim();
  const match = /^(sha256=)([0-9a-fA-F]+)$/.exec(value);
  if (match) {
    return { prefix: "sha256=", hex: match[2]!, rest: match[2]! };
  }
  return { prefix: null, hex: looksHex(value) ? value : null, rest: value };
}

function looksHex(value: string): boolean {
  return value.length % 2 === 0 && value.length >= 32 && /^[0-9a-fA-F]+$/.test(value);
}

export async function githubSign(input: SignInput): Promise<Record<string, string>> {
  const mac = await hmacSha256(input.secret, input.payload);
  return { [GITHUB_SIGNATURE_HEADER]: `sha256=${hexEncode(mac)}` };
}

export async function githubVerify(input: VerifyInput): Promise<VerifyOutcome> {
  const header = headerValue(input.headers, GITHUB_SIGNATURE_HEADER);
  if (!header) {
    return {
      ok: false,
      hmacMatch: false,
      missingHeaders: [GITHUB_SIGNATURE_HEADER],
      reason: "missing_header",
    };
  }
  const parsed = parseGithubSignature(header);
  const expected = await hmacSha256(input.secret, input.payload);
  const provided = parsed.hex ? hexToBytes(parsed.hex) : null;
  const bytesMatch = !!(provided && timingSafeEqualBytes(expected, provided));
  const hmacMatch = bytesMatch && parsed.prefix === "sha256=";
  return {
    ok: hmacMatch,
    hmacMatch,
    reason: hmacMatch ? undefined : "bad_signature",
  };
}

export async function githubHmacFor(secret: string, payload: Uint8Array): Promise<Uint8Array> {
  return hmacSha256(secret, payload);
}

export function stripGithubPrefix(value: string): string {
  return value.trim().replace(/^sha256=/i, "");
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

export const GITHUB_OFFICIAL_VECTOR = {
  secret: "It's a Secret to Everybody",
  payload: utf8Encode("Hello, World!"),
  payloadText: "Hello, World!",
  hex: "757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17",
  header: "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17",
};
