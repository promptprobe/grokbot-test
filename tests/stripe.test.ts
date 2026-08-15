import { describe, expect, it } from "vitest";
import { check } from "../src/check.ts";
import { stripeSign, stripeHmacRawBody } from "../src/providers/stripe.ts";
import { utf8Encode, hexEncode } from "../src/core/bytes.ts";
import { loadFixture } from "./helpers.ts";

const SECRET = "whsec_test_secret_stripe_aaaaaaaa";
const BODY = utf8Encode('{"id":"evt_whyhook_test"}');
const TS = 1_700_000_000;

describe("stripe", () => {
  it("verifies an implementation-independent frozen vector via check() only", async () => {
    const frozen = loadFixture<{
      secret: string;
      timestamp: number;
      payload: string;
      header: string;
    }>("stripe-independent.json");
    const result = await check({
      provider: "stripe",
      payload: utf8Encode(frozen.payload),
      secret: frozen.secret,
      headers: { "Stripe-Signature": frozen.header },
      now: frozen.timestamp,
    });
    expect(result.status).toBe("verified");
  });

  it("verifies a known t.payload vector", async () => {
    const headers = await stripeSign({ payload: BODY, secret: SECRET, timestamp: TS });
    const result = await check({
      provider: "stripe",
      payload: BODY,
      secret: SECRET,
      headers,
      now: TS,
    });
    expect(result.status).toBe("verified");
    expect(result.timestamp?.value).toBe(TS);
  });

  it("ignores extra v0 keys when v1 matches", async () => {
    const headers = await stripeSign({ payload: BODY, secret: SECRET, timestamp: TS });
    const v1 = headers["Stripe-Signature"];
    const withV0 = `${v1},v0=deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef`;
    const result = await check({
      provider: "stripe",
      payload: BODY,
      secret: SECRET,
      headers: { "Stripe-Signature": withV0 },
      now: TS,
    });
    expect(result.status).toBe("verified");
  });

  it("flags timestamp skew", async () => {
    const headers = await stripeSign({ payload: BODY, secret: SECRET, timestamp: TS });
    const result = await check({
      provider: "stripe",
      payload: BODY,
      secret: SECRET,
      headers,
      now: TS + 301,
      toleranceSeconds: 300,
    });
    expect(result.status).toBe("invalid");
    expect(result.diagnoses.some((d) => d.id === "timestamp-stale")).toBe(true);
    expect(result.timestamp?.withinTolerance).toBe(false);
  });

  it("diagnoses raw-body HMAC vs t.payload", async () => {
    const rawMac = await stripeHmacRawBody(SECRET, BODY);
    const header = `t=${TS},v1=${hexEncode(rawMac)}`;
    const result = await check({
      provider: "stripe",
      payload: BODY,
      secret: SECRET,
      headers: { "Stripe-Signature": header },
      now: TS,
    });
    expect(result.status).toBe("invalid");
    expect(result.diagnoses.some((d) => d.id === "stripe-raw-body")).toBe(true);
  });

  it("rotates across multiple v1 signatures", async () => {
    const a = await stripeSign({ payload: BODY, secret: "secret_a_stripe_test", timestamp: TS });
    const b = await stripeSign({ payload: BODY, secret: "secret_b_stripe_test", timestamp: TS });
    const t = `t=${TS}`;
    const v1a = a["Stripe-Signature"]!.split(",").find((p) => p.startsWith("v1="));
    const v1b = b["Stripe-Signature"]!.split(",").find((p) => p.startsWith("v1="));
    const combined = `${t},${v1a},${v1b}`;
    const ra = await check({
      provider: "stripe",
      payload: BODY,
      secret: "secret_a_stripe_test",
      headers: { "Stripe-Signature": combined },
      now: TS,
    });
    const rb = await check({
      provider: "stripe",
      payload: BODY,
      secret: "secret_b_stripe_test",
      headers: { "Stripe-Signature": combined },
      now: TS,
    });
    expect(ra.status).toBe("verified");
    expect(rb.status).toBe("verified");
  });
});
