const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const decoderLoose = new TextDecoder("utf-8", { fatal: false });

export function utf8Encode(text: string): Uint8Array {
  return encoder.encode(text);
}

export function utf8Decode(bytes: Uint8Array): string | null {
  try {
    return decoder.decode(bytes);
  } catch {
    return null;
  }
}

export function utf8DecodeLossy(bytes: Uint8Array): string {
  return decoderLoose.decode(bytes);
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

export function endsWithBytes(data: Uint8Array, suffix: number[]): boolean {
  if (data.length < suffix.length) return false;
  const start = data.length - suffix.length;
  for (let i = 0; i < suffix.length; i++) {
    if (data[start + i] !== suffix[i]) return false;
  }
  return true;
}

export function startsWithBytes(data: Uint8Array, prefix: number[]): boolean {
  if (data.length < prefix.length) return false;
  for (let i = 0; i < prefix.length; i++) {
    if (data[i] !== prefix[i]) return false;
  }
  return true;
}

export function hexEncode(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i]!.toString(16).padStart(2, "0");
  }
  return out;
}

export function hexDecode(hex: string): Uint8Array | null {
  const clean = hex.trim().toLowerCase();
  if (clean.length === 0 || clean.length % 2 !== 0) return null;
  if (!/^[0-9a-f]+$/.test(clean)) return null;
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function base64Encode(bytes: Uint8Array): string {
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

export function base64Decode(value: string): Uint8Array | null {
  const clean = value.trim().replace(/\s+/g, "");
  if (clean.length === 0) return null;
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(clean)) return null;
  try {
    const binary = atob(clean);
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      out[i] = binary.charCodeAt(i);
    }
    return out;
  } catch {
    return null;
  }
}

export function timingSafeEqualBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    let acc = 0;
    const n = Math.max(a.length, 1);
    for (let i = 0; i < n; i++) {
      acc |= (a[i % a.length] ?? 0) ^ (b[i % b.length] ?? 0);
    }
    return acc === 0 && a.length === b.length;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i]! ^ b[i]!;
  }
  return diff === 0;
}

export function timingSafeEqualHex(a: string, b: string): boolean {
  const left = hexDecode(a);
  const right = hexDecode(b);
  if (!left || !right) return false;
  return timingSafeEqualBytes(left, right);
}

export function timingSafeEqualBase64(a: string, b: string): boolean {
  const left = base64Decode(a);
  const right = base64Decode(b);
  if (!left || !right) return false;
  return timingSafeEqualBytes(left, right);
}

export function looksLikeHex(value: string): boolean {
  const clean = value.trim();
  return clean.length % 2 === 0 && clean.length >= 32 && /^[0-9a-fA-F]+$/.test(clean);
}

export function looksLikeBase64(value: string): boolean {
  const clean = value.trim().replace(/\s+/g, "");
  return clean.length >= 24 && /^[A-Za-z0-9+/]+={0,2}$/.test(clean) && !looksLikeHex(clean);
}
