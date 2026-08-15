import { describe, expect, it } from "vitest";
import { check } from "../src/check.ts";
import { slackSign, slackHmac } from "../src/providers/slack.ts";
import { utf8Encode, hexEncode } from "../src/core/bytes.ts";

const SECRET = "slack_test_signing_secret_0001";
const BODY = utf8Encode('{"type":"event_callback"}');
const TS = 1_710_000_000;

describe("slack", () => {
  it("verifies a known v0 vector", async () => {
    const headers = await slackSign({ payload: BODY, secret: SECRET, timestamp: TS });
    const result = await check({
      provider: "slack",
      payload: BODY,
      secret: SECRET,
      headers,
      now: TS,
    });
    expect(result.status).toBe("verified");
  });

  it("accepts timestamp header as a string of digits", async () => {
    const headers = await slackSign({ payload: BODY, secret: SECRET, timestamp: TS });
    headers["X-Slack-Request-Timestamp"] = String(TS);
    const result = await check({
      provider: "slack",
      payload: BODY,
      secret: SECRET,
      headers,
      now: TS,
    });
    expect(result.status).toBe("verified");
  });

  it("flags timestamp skew", async () => {
    const headers = await slackSign({ payload: BODY, secret: SECRET, timestamp: TS });
    const result = await check({
      provider: "slack",
      payload: BODY,
      secret: SECRET,
      headers,
      now: TS + 400,
    });
    expect(result.status).toBe("invalid");
    expect(result.diagnoses.some((d) => d.id === "timestamp-stale")).toBe(true);
  });

  it("diagnoses missing v0: basestring prefix", async () => {
    const mac = await slackHmac(SECRET, String(TS), BODY, false);
    const result = await check({
      provider: "slack",
      payload: BODY,
      secret: SECRET,
      headers: {
        "X-Slack-Request-Timestamp": String(TS),
        "X-Slack-Signature": `v0=${hexEncode(mac)}`,
      },
      now: TS,
    });
    expect(result.status).toBe("invalid");
    expect(result.diagnoses.some((d) => d.id === "slack-missing-v0-colon")).toBe(true);
  });
});
