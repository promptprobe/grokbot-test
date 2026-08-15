import type { ProviderId, SignInput, VerifyInput, VerifyOutcome } from "../core/types.ts";
import { githubSign, githubVerify } from "./github.ts";
import { slackSign, slackVerify } from "./slack.ts";
import { standardSign, standardVerify } from "./standard.ts";
import { stripeSign, stripeVerify } from "./stripe.ts";
import { headerValue } from "../core/headers.ts";

export const PROVIDERS: ProviderId[] = ["github", "stripe", "slack", "standard"];

export function isProviderId(value: string): value is ProviderId {
  return (PROVIDERS as string[]).includes(value);
}

export async function verifyProvider(
  provider: ProviderId,
  input: VerifyInput,
): Promise<VerifyOutcome> {
  switch (provider) {
    case "github":
      return githubVerify(input);
    case "stripe":
      return stripeVerify(input);
    case "slack":
      return slackVerify(input);
    case "standard":
      return standardVerify(input);
  }
}

export async function signProvider(
  provider: ProviderId,
  input: SignInput,
): Promise<Record<string, string>> {
  switch (provider) {
    case "github":
      return githubSign(input);
    case "stripe":
      return stripeSign(input);
    case "slack":
      return slackSign(input);
    case "standard":
      return standardSign(input);
  }
}

export function detectProvider(headers: Record<string, string>): ProviderId | undefined {
  const hits: ProviderId[] = [];
  if (headerValue(headers, "X-Hub-Signature-256") || headerValue(headers, "X-Hub-Signature")) {
    hits.push("github");
  }
  if (headerValue(headers, "Stripe-Signature")) hits.push("stripe");
  if (
    headerValue(headers, "X-Slack-Signature") ||
    headerValue(headers, "X-Slack-Request-Timestamp")
  ) {
    hits.push("slack");
  }
  if (
    headerValue(headers, "webhook-signature") ||
    headerValue(headers, "webhook-id") ||
    headerValue(headers, "webhook-timestamp")
  ) {
    hits.push("standard");
  }
  if (hits.length === 1) return hits[0];
  return undefined;
}

export function requiredHeaders(provider: ProviderId): string[] {
  switch (provider) {
    case "github":
      return ["X-Hub-Signature-256"];
    case "stripe":
      return ["Stripe-Signature"];
    case "slack":
      return ["X-Slack-Request-Timestamp", "X-Slack-Signature"];
    case "standard":
      return ["webhook-id", "webhook-timestamp", "webhook-signature"];
  }
}
