import { describe, expect, it } from "vitest";
import { check } from "../src/check.ts";
import { githubSign } from "../src/providers/github.ts";
import { stripeSign } from "../src/providers/stripe.ts";
import { slackSign } from "../src/providers/slack.ts";
import { utf8Encode, hexEncode, base64Encode } from "../src/core/bytes.ts";
import { hmacSha256 } from "../src/core/crypto.ts";

describe("input errors", () => {
  it("empty secret does not throw", async () => {
    const result = await check({
      provider: "github",
      payload: utf8Encode("x"),
      secret: "",
      headers: { "X-Hub-Signature-256": "sha256=aa" },
    });
    expect(result.status).toBe("error");
  });

  it("missing headers do not throw", async () => {
    const result = await check({
      provider: "slack",
      payload: utf8Encode("x"),
      secret: "abc",
      headers: {},
    });
    expect(result.status).toBe("error");
    expect(result.message).toMatch(/Missing required header/);
  });
});

describe("payload shapes", () => {
  it("verifies a 400KB payload", async () => {
    const payload = utf8Encode("a".repeat(400_000));
    const headers = await githubSign({ payload, secret: "big_payload_secret" });
    const result = await check({
      provider: "github",
      payload,
      secret: "big_payload_secret",
      headers,
    });
    expect(result.status).toBe("verified");
  });

  it("verifies a binary-looking body", async () => {
    const payload = Uint8Array.from([0xff, 0xfe, 0x00, 0x01, 0x80, 0x7f, 10, 13]);
    const headers = await githubSign({ payload, secret: "binary_secret_0001" });
    const result = await check({
      provider: "github",
      payload,
      secret: "binary_secret_0001",
      headers,
    });
    expect(result.status).toBe("verified");
  });

  it("diagnoses UTF-8 BOM", async () => {
    const body = utf8Encode('{"a":1}');
    const headers = await githubSign({ payload: body, secret: "bom_secret" });
    const bom = new Uint8Array(3 + body.length);
    bom.set([0xef, 0xbb, 0xbf], 0);
    bom.set(body, 3);
    const result = await check({
      provider: "github",
      payload: bom,
      secret: "bom_secret",
      headers,
    });
    expect(result.status).toBe("invalid");
    expect(result.diagnoses.some((d) => d.id === "utf8-bom-present")).toBe(true);
  });
});

describe("encoding diagnoses", () => {
  it("github hex vs base64", async () => {
    const payload = utf8Encode("Hello, World!");
    const mac = await hmacSha256("enc_secret", payload);
    const result = await check({
      provider: "github",
      payload,
      secret: "enc_secret",
      headers: { "X-Hub-Signature-256": `sha256=${base64Encode(mac)}` },
    });
    expect(result.status).toBe("invalid");
    expect(result.diagnoses.some((d) => d.id === "encoding-hex-vs-base64")).toBe(true);
  });
});

describe("header case", () => {
  it("stripe mixed-case header name verifies", async () => {
    const payload = utf8Encode("{}");
    const ts = 1_730_000_000;
    const signed = await stripeSign({ payload, secret: "s", timestamp: ts });
    const result = await check({
      provider: "stripe",
      payload,
      secret: "s",
      headers: { "stripe-signature": signed["Stripe-Signature"]! },
      now: ts,
    });
    expect(result.status).toBe("verified");
  });

  it("slack mixed-case header names verify", async () => {
    const payload = utf8Encode("ok");
    const ts = 1_730_000_001;
    const signed = await slackSign({ payload, secret: "slack_secret", timestamp: ts });
    const result = await check({
      provider: "slack",
      payload,
      secret: "slack_secret",
      headers: {
        "x-slack-request-timestamp": signed["X-Slack-Request-Timestamp"]!,
        "x-slack-signature": signed["X-Slack-Signature"]!,
      },
      now: ts,
    });
    expect(result.status).toBe("verified");
  });
});

describe("hex helper used in tests", () => {
  it("roundtrips", () => {
    expect(hexEncode(Uint8Array.from([0xab, 0xcd]))).toBe("abcd");
  });
});
