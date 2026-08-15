import { base64Encode, hexEncode, utf8Encode } from "./bytes.ts";

function getSubtle() {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) {
    throw new Error("Web Crypto SubtleCrypto is not available");
  }
  return subtle;
}

export async function hmacSha256(
  secret: Uint8Array | string,
  payload: Uint8Array | string,
): Promise<Uint8Array> {
  const keyBytes = typeof secret === "string" ? utf8Encode(secret) : secret;
  const data = typeof payload === "string" ? utf8Encode(payload) : payload;
  const key = await getSubtle().importKey(
    "raw",
    toArrayBuffer(keyBytes),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await getSubtle().sign("HMAC", key, toArrayBuffer(data));
  return new Uint8Array(sig);
}

export async function hmacSha256Hex(
  secret: Uint8Array | string,
  payload: Uint8Array | string,
): Promise<string> {
  return hexEncode(await hmacSha256(secret, payload));
}

export async function hmacSha256Base64(
  secret: Uint8Array | string,
  payload: Uint8Array | string,
): Promise<string> {
  return base64Encode(await hmacSha256(secret, payload));
}

export async function sha256Hex(data: Uint8Array | string): Promise<string> {
  const bytes = typeof data === "string" ? utf8Encode(data) : data;
  const digest = await getSubtle().digest("SHA-256", toArrayBuffer(bytes));
  return hexEncode(new Uint8Array(digest));
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes);
  return copy.buffer;
}
