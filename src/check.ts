import { DEFAULT_TOLERANCE_SECONDS, type CheckInput, type CheckResult } from "./core/types.ts";
import { secretHint, unixNowSeconds } from "./core/headers.ts";
import { diagnose } from "./diagnose.ts";
import {
  detectProvider,
  isProviderId,
  requiredHeaders,
  verifyProvider,
} from "./providers/index.ts";
import { headerValue } from "./core/headers.ts";

export function resolveProvider(
  requested: string | undefined,
  headers: Record<string, string>,
): { provider?: CheckResult["provider"]; error?: string } {
  if (requested) {
    if (!isProviderId(requested)) {
      return {
        error: `Unknown provider "${requested}". Use github, stripe, slack, or standard.`,
      };
    }
    return { provider: requested };
  }
  const detected = detectProvider(headers);
  if (!detected) {
    return {
      error:
        "Could not detect provider from headers. Pass --provider github|stripe|slack|standard.",
    };
  }
  return { provider: detected };
}

export async function check(input: CheckInput): Promise<CheckResult> {
  const secret = input.secret;
  if (typeof secret !== "string" || secret.length === 0) {
    return {
      status: "error",
      verified: false,
      message: "Secret is empty. Provide the webhook signing secret.",
      diagnoses: [],
    };
  }

  const resolved = resolveProvider(input.provider, input.headers);
  if (!resolved.provider) {
    return {
      status: "error",
      verified: false,
      message: resolved.error ?? "Provider is required.",
      diagnoses: [],
      secret: secretHint(secret),
    };
  }
  const provider = resolved.provider;
  const missing = requiredHeaders(provider).filter(
    (name) => !headerValue(input.headers, name),
  );
  if (missing.length) {
    return {
      status: "error",
      provider,
      verified: false,
      message: `Missing required header${missing.length > 1 ? "s" : ""}: ${missing.join(", ")}.`,
      diagnoses: [],
      secret: secretHint(secret),
    };
  }

  const verifyInput = {
    payload: input.payload,
    secret,
    headers: input.headers,
    now: unixNowSeconds(input.now),
    toleranceSeconds: input.toleranceSeconds ?? DEFAULT_TOLERANCE_SECONDS,
  };

  const outcome = await verifyProvider(provider, verifyInput);
  if (outcome.missingHeaders?.length) {
    return {
      status: "error",
      provider,
      verified: false,
      message: `Missing required header${outcome.missingHeaders.length > 1 ? "s" : ""}: ${outcome.missingHeaders.join(", ")}.`,
      diagnoses: [],
      secret: secretHint(secret),
      timestamp: outcome.timestamp,
    };
  }

  if (outcome.ok) {
    return {
      status: "verified",
      provider,
      verified: true,
      message: verifiedMessage(provider),
      diagnoses: [],
      secret: secretHint(secret),
      timestamp: outcome.timestamp,
    };
  }

  const diagnoses = await diagnose(provider, verifyInput);
  return {
    status: "invalid",
    provider,
    verified: false,
    message: invalidMessage(provider, outcome.reason),
    diagnoses,
    secret: secretHint(secret),
    timestamp: outcome.timestamp,
  };
}

function verifiedMessage(provider: CheckInput["provider"]): string {
  switch (provider) {
    case "github":
      return "GitHub HMAC-SHA256 (X-Hub-Signature-256) matched the raw body.";
    case "stripe":
      return "Stripe v1 HMAC-SHA256 matched t.payload and the timestamp is within tolerance.";
    case "slack":
      return "Slack v0 HMAC-SHA256 matched v0:timestamp:body and the timestamp is within tolerance.";
    case "standard":
      return "Standard Webhooks v1 HMAC-SHA256 matched id.timestamp.payload and the timestamp is within tolerance.";
    default:
      return "Signature verified.";
  }
}

function invalidMessage(provider: CheckInput["provider"], reason?: string): string {
  if (reason === "stale_timestamp") {
    return "HMAC matches but the timestamp is outside the tolerance window.";
  }
  if (reason === "bad_secret") {
    return "The secret could not be decoded. Standard Webhooks secrets are whsec_ plus base64.";
  }
  if (reason === "bad_timestamp") {
    return "The timestamp header is not a unix-seconds integer.";
  }
  switch (provider) {
    case "github":
      return "GitHub signature did not match this body and secret.";
    case "stripe":
      return "Stripe signature did not match this body, secret, and timestamp.";
    case "slack":
      return "Slack signature did not match this body, secret, and timestamp.";
    case "standard":
      return "Standard Webhooks signature did not match this body, secret, and timestamp.";
    default:
      return "Signature did not match.";
  }
}
