import { utf8Decode, utf8Encode, base64Encode } from "./core/bytes.ts";
import type { ProviderId, Vector } from "./core/types.ts";
import { signProvider } from "./providers/index.ts";

const DEFAULT_PAYLOADS: Record<ProviderId, string> = {
  github: "Hello, World!",
  stripe: '{"id":"evt_whyhook_test","object":"event"}',
  slack: '{"type":"event_callback","challenge":"whyhook"}',
  standard: '{"hello":"whyhook"}',
};

const DEFAULT_SECRETS: Record<ProviderId, string> = {
  github: "It's a Secret to Everybody",
  stripe: "whsec_test_secret_stripe_aaaaaaaa",
  slack: "slack_test_signing_secret_0001",
  standard: "whsec_dGVzdF9zdGFuZGFyZF93ZWJob29rX3NlY3JldA==",
};

export async function generateVector(options: {
  provider: ProviderId;
  payload?: Uint8Array;
  secret?: string;
  timestamp?: number;
  id?: string;
}): Promise<Vector> {
  const payload = options.payload ?? utf8Encode(DEFAULT_PAYLOADS[options.provider]);
  const secret = options.secret ?? DEFAULT_SECRETS[options.provider];
  const headers = await signProvider(options.provider, {
    payload,
    secret,
    timestamp: options.timestamp,
    id: options.id,
  });
  const asText = utf8Decode(payload);
  return {
    provider: options.provider,
    payload: asText ?? base64Encode(payload),
    payloadEncoding: asText === null ? "base64" : "utf8",
    secret,
    headers,
    notes: notesFor(options.provider),
  };
}

function notesFor(provider: ProviderId): string {
  switch (provider) {
    case "github":
      return "GitHub HMAC-SHA256 of the raw body. Header X-Hub-Signature-256: sha256=<hex>.";
    case "stripe":
      return "Stripe signs `${t}.${payload}` with HMAC-SHA256 hex. Extra v0= keys are ignored.";
    case "slack":
      return "Slack signs `v0:${timestamp}:${body}` with HMAC-SHA256. Header v0=<hex>.";
    case "standard":
      return "Standard Webhooks signs `id.timestamp.payload`. Secret is base64 after optional whsec_ prefix. Signature v1,<base64>.";
  }
}

export function vectorToCli(vector: Vector): string {
  const headers = Object.entries(vector.headers)
    .map(([name, value]) => `--header ${shellQuote(`${name}: ${value}`)}`)
    .join(" \\\n  ");
  return [
    `whyhook check --provider ${vector.provider} \\`,
    `  --secret ${shellQuote(vector.secret)} \\`,
    `  ${headers} \\`,
    `  --payload-file - <<'PAYLOAD'`,
    vector.payloadEncoding === "utf8" ? vector.payload : `<base64:${vector.payload}>`,
    "PAYLOAD",
  ].join("\n");
}

function shellQuote(value: string): string {
  if (/^[A-Za-z0-9_./:=,@-]+$/.test(value)) return value;
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

export { DEFAULT_PAYLOADS, DEFAULT_SECRETS };
