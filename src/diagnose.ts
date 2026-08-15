import {
  concatBytes,
  endsWithBytes,
  startsWithBytes,
  utf8Decode,
  utf8Encode,
  hexEncode,
  base64Encode,
  base64Decode,
  hexDecode,
  timingSafeEqualBytes,
} from "./core/bytes.ts";
import type { Diagnosis, Hypothesis, ProviderId, VerifyInput } from "./core/types.ts";
import { headerValue } from "./core/headers.ts";
import {
  githubHmacFor,
  parseGithubSignature,
  stripGithubPrefix,
} from "./providers/github.ts";
import {
  parseStripeSignature,
  stripeHmacRawBody,
  stripeHmacSigned,
} from "./providers/stripe.ts";
import {
  parseSlackSignature,
  slackHmac,
} from "./providers/slack.ts";
import {
  decodeStandardSecret,
  parseStandardSignatures,
  standardHmacWithKey,
} from "./providers/standard.ts";
import { verifyProvider } from "./providers/index.ts";

const LF = [0x0a];
const CRLF = [0x0d, 0x0a];
const BOM = [0xef, 0xbb, 0xbf];

interface PayloadVariant {
  id: string;
  rank: number;
  title: string;
  detail: string;
  confidence: Diagnosis["confidence"];
  payload: Uint8Array;
}

function payloadVariants(payload: Uint8Array): PayloadVariant[] {
  const variants: PayloadVariant[] = [];
  const text = utf8Decode(payload);

  if (endsWithBytes(payload, CRLF)) {
    variants.push({
      id: "trailing-crlf",
      rank: 10,
      title: "Trailing CRLF in the body",
      detail:
        "Removing a trailing \\r\\n from the payload makes the HMAC match. Proxies and editors often add Windows newlines.",
      confidence: "high",
      payload: payload.slice(0, -2),
    });
  } else if (endsWithBytes(payload, LF)) {
    variants.push({
      id: "trailing-lf",
      rank: 10,
      title: "Trailing newline in the body",
      detail:
        "Removing a trailing \\n from the payload makes the HMAC match. Many HTTP clients or JSON pretty-printers add one.",
      confidence: "high",
      payload: payload.slice(0, -1),
    });
  } else {
    variants.push({
      id: "missing-lf",
      rank: 22,
      title: "Missing trailing newline",
      detail: "HMAC matches if a trailing \\n is appended to the payload.",
      confidence: "medium",
      payload: concatBytes(payload, Uint8Array.from(LF)),
    });
    variants.push({
      id: "missing-crlf",
      rank: 24,
      title: "Missing trailing CRLF",
      detail: "HMAC matches if a trailing \\r\\n is appended to the payload.",
      confidence: "low",
      payload: concatBytes(payload, Uint8Array.from(CRLF)),
    });
  }

  if (startsWithBytes(payload, BOM)) {
    variants.push({
      id: "utf8-bom-present",
      rank: 12,
      title: "UTF-8 BOM at start of body",
      detail:
        "Stripping the UTF-8 byte-order mark (EF BB BF) makes the HMAC match. Some editors save JSON with a BOM.",
      confidence: "high",
      payload: payload.slice(3),
    });
  } else {
    variants.push({
      id: "utf8-bom-missing",
      rank: 26,
      title: "Missing UTF-8 BOM",
      detail: "HMAC matches if a UTF-8 BOM is prepended to the payload.",
      confidence: "low",
      payload: concatBytes(Uint8Array.from(BOM), payload),
    });
  }

  if (text !== null) {
    try {
      const parsed: unknown = JSON.parse(text);
      const min = JSON.stringify(parsed);
      const pretty = JSON.stringify(parsed, null, 2);
      if (min !== text) {
        variants.push({
          id: "json-minify",
          rank: 11,
          title: "JSON was re-serialized (minified)",
          detail:
            "JSON.parse + JSON.stringify (compact, no extra spaces) produces a body whose HMAC matches. The signature was computed over a different serialization than the one you pasted.",
          confidence: "high",
          payload: utf8Encode(min),
        });
      }
      if (pretty !== text) {
        variants.push({
          id: "json-pretty-2",
          rank: 14,
          title: "JSON was re-serialized (2-space pretty-print)",
          detail:
            "JSON.parse + JSON.stringify(value, null, 2) produces a body whose HMAC matches. Pretty-printing or collapsing whitespace changed the raw bytes.",
          confidence: "high",
          payload: utf8Encode(pretty),
        });
      }
    } catch {
      // not JSON
    }
    const trimmed = text.trim();
    if (trimmed !== text) {
      variants.push({
        id: "trim-whitespace",
        rank: 18,
        title: "Leading or trailing whitespace",
        detail: "Trimming the payload makes the HMAC match.",
        confidence: "medium",
        payload: utf8Encode(trimmed),
      });
    }
  }

  return variants;
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && timingSafeEqualBytes(a, b);
}

async function hmacMatches(
  provider: ProviderId,
  input: VerifyInput,
): Promise<boolean> {
  const outcome = await verifyProvider(provider, {
    ...input,
    now: input.now,
    toleranceSeconds: Number.MAX_SAFE_INTEGER,
  });
  return outcome.hmacMatch;
}

export async function diagnose(
  provider: ProviderId,
  input: VerifyInput,
): Promise<Diagnosis[]> {
  const hits: Diagnosis[] = [];
  const seen = new Set<string>();

  const push = (d: Diagnosis) => {
    if (seen.has(d.id)) return;
    seen.add(d.id);
    hits.push(d);
  };

  const canonical = await verifyProvider(provider, input);
  if (canonical.reason === "stale_timestamp") {
    push({
      id: "timestamp-stale",
      rank: 5,
      title: "Timestamp is outside the tolerance window",
      detail: canonical.timestamp
        ? `The HMAC matches, but the webhook timestamp is ${canonical.timestamp.skewSeconds}s off (tolerance ${canonical.timestamp.toleranceSeconds}s). Check local clock skew, or that you copied the original timestamp.`
        : "The HMAC matches, but the timestamp is outside the configured tolerance.",
      confidence: "high",
    });
  }
  if (canonical.reason === "missing_v1" && provider === "stripe") {
    push({
      id: "stripe-v0-only",
      rank: 19,
      title: "Only v0 signatures present",
      detail:
        "The Stripe-Signature header has v0= keys but no v1=. Current Stripe verifiers expect v1 HMAC-SHA256.",
      confidence: "high",
    });
  }

  for (const variant of payloadVariants(input.payload)) {
    if (sameBytes(variant.payload, input.payload)) continue;
    const match = await hmacMatches(provider, { ...input, payload: variant.payload });
    if (match) {
      push({
        id: variant.id,
        rank: variant.rank,
        title: variant.title,
        detail: variant.detail,
        confidence: variant.confidence,
      });
    }
  }

  for (const hypo of await providerHypotheses(provider, input)) {
    const candidate: VerifyInput = {
      ...input,
      payload: hypo.payload ?? input.payload,
      secret: hypo.secret ?? input.secret,
      headers: hypo.headers ?? input.headers,
      toleranceSeconds: hypo.ignoreTolerance ? Number.MAX_SAFE_INTEGER : input.toleranceSeconds,
    };
    if (hypo.scheme) {
      const match = await schemeMatch(provider, candidate, hypo.scheme);
      if (match) {
        push({
          id: hypo.id,
          rank: hypo.rank,
          title: hypo.title,
          detail: hypo.detail,
          confidence: hypo.confidence,
        });
      }
      continue;
    }
    const match = await hmacMatches(provider, candidate);
    if (match) {
      push({
        id: hypo.id,
        rank: hypo.rank,
        title: hypo.title,
        detail: hypo.detail,
        confidence: hypo.confidence,
      });
    }
  }

  hits.sort((a, b) => a.rank - b.rank || a.id.localeCompare(b.id));
  return hits;
}

async function providerHypotheses(
  provider: ProviderId,
  input: VerifyInput,
): Promise<Hypothesis[]> {
  switch (provider) {
    case "github":
      return githubHypotheses(input);
    case "stripe":
      return stripeHypotheses();
    case "slack":
      return slackHypotheses(input);
    case "standard":
      return standardHypotheses(input);
  }
}

async function githubHypotheses(input: VerifyInput): Promise<Hypothesis[]> {
  const raw = headerValue(input.headers, "X-Hub-Signature-256") ?? "";
  const parsed = parseGithubSignature(raw);
  const hypos: Hypothesis[] = [];
  if (raw && !parsed.prefix) {
    hypos.push({
      id: "prefix-absent",
      rank: 8,
      title: "Missing sha256= signature prefix",
      detail:
        "GitHub sends X-Hub-Signature-256 as sha256=<hex>. The hex itself matches; add the sha256= prefix, or verify against the hex portion only.",
      confidence: "high",
      headers: { ...input.headers, "X-Hub-Signature-256": `sha256=${raw.trim()}` },
    });
  }
  hypos.push({
    id: "encoding-hex-vs-base64",
    rank: 16,
    title: "Signature is base64 instead of hex",
    detail:
      "GitHub signatures are lowercase hex. Interpreting the header as base64 (or comparing to a base64 HMAC) matches the computed MAC.",
    confidence: "medium",
    scheme: "github-base64",
  });
  return hypos;
}

async function stripeHypotheses(): Promise<Hypothesis[]> {
  const hypos: Hypothesis[] = [];
  hypos.push({
    id: "stripe-raw-body",
    rank: 9,
    title: "Signed the raw body instead of t.payload",
    detail:
      "Stripe signs `${timestamp}.${rawBody}`. HMAC of the raw body alone matches the v1 signature — the timestamp prefix was omitted when computing or verifying.",
    confidence: "high",
    scheme: "stripe-raw-body",
  });
  hypos.push({
    id: "encoding-hex-vs-base64",
    rank: 16,
    title: "v1 signature encoded as base64 instead of hex",
    detail: "Stripe v1 signatures are hex. A base64 encoding of the same HMAC matches.",
    confidence: "medium",
    scheme: "stripe-base64",
  });
  return hypos;
}

async function slackHypotheses(input: VerifyInput): Promise<Hypothesis[]> {
  const hypos: Hypothesis[] = [];
  const sig = headerValue(input.headers, "X-Slack-Signature") ?? "";
  const parsed = parseSlackSignature(sig);
  if (sig && !parsed.prefix) {
    hypos.push({
      id: "prefix-absent",
      rank: 8,
      title: "Missing v0= signature prefix",
      detail:
        "Slack sends X-Slack-Signature as v0=<hex>. The hex matches; add the v0= prefix.",
      confidence: "high",
      headers: { ...input.headers, "X-Slack-Signature": `v0=${sig.trim()}` },
    });
  }
  hypos.push({
    id: "slack-missing-v0-colon",
    rank: 9,
    title: "Signed string missing v0: prefix",
    detail:
      "Slack's signed basestring is `v0:${timestamp}:${body}`. HMAC of `${timestamp}:${body}` (no v0:) matches the header — the version prefix was dropped.",
    confidence: "high",
    scheme: "slack-no-v0-basestring",
  });
  hypos.push({
    id: "encoding-hex-vs-base64",
    rank: 16,
    title: "Signature is base64 instead of hex",
    detail: "Slack signatures are hex after v0=. A base64 encoding of the same HMAC matches.",
    confidence: "medium",
    scheme: "slack-base64",
  });
  return hypos;
}

async function standardHypotheses(input: VerifyInput): Promise<Hypothesis[]> {
  const hypos: Hypothesis[] = [];
  const secret = input.secret;
  if (secret.startsWith("whsec_")) {
    hypos.push({
      id: "standard-secret-as-utf8",
      rank: 15,
      title: "Secret used as UTF-8 instead of base64",
      detail:
        "Standard Webhooks secrets are `whsec_` plus base64-encoded key bytes. Treating the whole string (or the part after whsec_) as a UTF-8 HMAC key matches.",
      confidence: "medium",
      scheme: "standard-utf8-secret",
    });
  } else {
    hypos.push({
      id: "standard-secret-without-whsec",
      rank: 8,
      title: "Secret missing whsec_ prefix",
      detail:
        "Decoding the secret as base64 (Standard Webhooks format, as if a whsec_ prefix had been stripped) makes the HMAC match. Add or strip the prefix consistently.",
      confidence: "high",
      secret: secret.startsWith("whsec_") ? secret : `whsec_${secret}`,
    });
    hypos.push({
      id: "standard-secret-with-whsec",
      rank: 8,
      title: "whsec_ prefix should be stripped before base64-decode",
      detail:
        "If the stored secret includes `whsec_` and you HMAC with the whole string, strip the prefix and base64-decode the remainder.",
      confidence: "high",
      scheme: "standard-utf8-secret",
    });
  }
  hypos.push({
    id: "encoding-base64-vs-hex",
    rank: 16,
    title: "Signature is hex instead of base64",
    detail:
      "Standard Webhooks v1 signatures are base64. A hex encoding of the same HMAC matches the computed MAC.",
    confidence: "medium",
    scheme: "standard-hex",
  });
  return hypos;
}

async function schemeMatch(
  provider: ProviderId,
  input: VerifyInput,
  scheme: string,
): Promise<boolean> {
  if (provider === "github") {
    const header = headerValue(input.headers, "X-Hub-Signature-256") ?? "";
    const expected = await githubHmacFor(input.secret, input.payload);
    if (scheme === "github-base64") {
      const provided =
        base64Decode(stripGithubPrefix(header)) ??
        hexDecode(stripGithubPrefix(header));
      if (provided && timingSafeEqualBytes(expected, provided) && !hexDecode(stripGithubPrefix(header))) {
        return true;
      }
      const b64 = base64Encode(expected);
      const rest = stripGithubPrefix(header);
      return rest === b64;
    }
  }
  if (provider === "stripe") {
    const header = headerValue(input.headers, "Stripe-Signature") ?? "";
    const parsed = parseStripeSignature(header);
    if (parsed.timestamp === null) return false;
    if (scheme === "stripe-raw-body") {
      const expected = await stripeHmacRawBody(input.secret, input.payload);
      return parsed.v1.some((v) => {
        const b = hexDecode(v);
        return b !== null && timingSafeEqualBytes(expected, b);
      });
    }
    if (scheme === "stripe-base64") {
      const expected = await stripeHmacSigned(input.secret, parsed.timestamp, input.payload);
      const b64 = base64Encode(expected);
      return parsed.v1.includes(b64);
    }
  }
  if (provider === "slack") {
    const ts = headerValue(input.headers, "X-Slack-Request-Timestamp") ?? "";
    const sig = headerValue(input.headers, "X-Slack-Signature") ?? "";
    const parsed = parseSlackSignature(sig);
    if (scheme === "slack-no-v0-basestring") {
      const expected = await slackHmac(input.secret, ts, input.payload, false);
      const hex = hexEncode(expected);
      return parsed.hex?.toLowerCase() === hex;
    }
    if (scheme === "slack-base64") {
      const expected = await slackHmac(input.secret, ts, input.payload, true);
      const rest = sig.replace(/^v0=/i, "");
      return rest === base64Encode(expected);
    }
  }
  if (provider === "standard") {
    const id = headerValue(input.headers, "webhook-id") ?? "";
    const ts = headerValue(input.headers, "webhook-timestamp") ?? "";
    const sigHeader = headerValue(input.headers, "webhook-signature") ?? "";
    const sigs = parseStandardSignatures(sigHeader);
    if (scheme === "standard-utf8-secret") {
      const withPayload = await standardHmacWithKey(
        utf8Encode(input.secret),
        id,
        ts,
        input.payload,
      );
      return sigs.some((s) => {
        const provided = base64Decode(s.value) ?? hexDecode(s.value);
        return provided !== null && timingSafeEqualBytes(withPayload, provided);
      });
    }
    if (scheme === "standard-hex") {
      const key = decodeStandardSecret(input.secret);
      if (!key) return false;
      const expected = await standardHmacWithKey(key, id, ts, input.payload);
      const hex = hexEncode(expected);
      return sigs.some((s) => s.value.toLowerCase() === hex);
    }
  }
  return false;
}
