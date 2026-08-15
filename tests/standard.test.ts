import { describe, expect, it } from "vitest";
import { check } from "../src/check.ts";
import { standardSign } from "../src/providers/standard.ts";
import { utf8Encode, base64Encode } from "../src/core/bytes.ts";
import { loadFixture } from "./helpers.ts";

const SECRET_A = "whsec_" + base64Encode(utf8Encode("test_standard_webhook_secret"));
const SECRET_B = "whsec_" + base64Encode(utf8Encode("rotated_standard_secret_b"));
const BODY = utf8Encode('{"hello":"whyhook"}');
const TS = 1_720_000_000;
const ID = "msg_whyhook_test_0001";

describe("standard webhooks", () => {
  it("verifies the Standard Webhooks official vector via check() only", async () => {
    const official = loadFixture<{
      secret: string;
      msgId: string;
      timestamp: string;
      payload: string;
      signature: string;
    }>("standard-official.json");
    const result = await check({
      provider: "standard",
      payload: utf8Encode(official.payload),
      secret: official.secret,
      headers: {
        "webhook-id": official.msgId,
        "webhook-timestamp": official.timestamp,
        "webhook-signature": official.signature,
      },
      now: Number(official.timestamp),
    });
    expect(result.status).toBe("verified");
  });

  it("verifies a known vector with whsec_ secret", async () => {
    const headers = await standardSign({
      payload: BODY,
      secret: SECRET_A,
      timestamp: TS,
      id: ID,
    });
    const result = await check({
      provider: "standard",
      payload: BODY,
      secret: SECRET_A,
      headers,
      now: TS,
    });
    expect(result.status).toBe("verified");
  });

  it("accepts the secret without the whsec_ prefix", async () => {
    const headers = await standardSign({
      payload: BODY,
      secret: SECRET_A,
      timestamp: TS,
      id: ID,
    });
    const result = await check({
      provider: "standard",
      payload: BODY,
      secret: SECRET_A.slice("whsec_".length),
      headers,
      now: TS,
    });
    expect(result.status).toBe("verified");
  });

  it("verifies either secret when multiple v1 signatures are present", async () => {
    const a = await standardSign({ payload: BODY, secret: SECRET_A, timestamp: TS, id: ID });
    const b = await standardSign({ payload: BODY, secret: SECRET_B, timestamp: TS, id: ID });
    const combined = `${a["webhook-signature"]} ${b["webhook-signature"]}`;
    const headers = {
      "webhook-id": ID,
      "webhook-timestamp": String(TS),
      "webhook-signature": combined,
    };
    const ra = await check({ provider: "standard", payload: BODY, secret: SECRET_A, headers, now: TS });
    const rb = await check({ provider: "standard", payload: BODY, secret: SECRET_B, headers, now: TS });
    const rc = await check({
      provider: "standard",
      payload: BODY,
      secret: "whsec_" + base64Encode(utf8Encode("unrelated_secret_bytes!!")),
      headers,
      now: TS,
    });
    expect(ra.status).toBe("verified");
    expect(rb.status).toBe("verified");
    expect(rc.status).toBe("invalid");
  });

  it("flags stale timestamp when HMAC would otherwise match", async () => {
    const headers = await standardSign({
      payload: BODY,
      secret: SECRET_A,
      timestamp: TS,
      id: ID,
    });
    const result = await check({
      provider: "standard",
      payload: BODY,
      secret: SECRET_A,
      headers,
      now: TS + 900,
      toleranceSeconds: 300,
    });
    expect(result.status).toBe("invalid");
    expect(result.diagnoses.some((d) => d.id === "timestamp-stale")).toBe(true);
  });

  it("is case-insensitive for header names", async () => {
    const signed = await standardSign({
      payload: BODY,
      secret: SECRET_A,
      timestamp: TS,
      id: ID,
    });
    const result = await check({
      provider: "standard",
      payload: BODY,
      secret: SECRET_A,
      headers: {
        "Webhook-Id": signed["webhook-id"]!,
        "WEBHOOK-TIMESTAMP": signed["webhook-timestamp"]!,
        "Webhook-Signature": signed["webhook-signature"]!,
      },
      now: TS,
    });
    expect(result.status).toBe("verified");
  });
});
