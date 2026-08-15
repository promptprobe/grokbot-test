import { describe, expect, it } from "vitest";
import { check } from "../src/check.ts";
import { GITHUB_OFFICIAL_VECTOR, githubSign } from "../src/providers/github.ts";
import { utf8Encode } from "../src/core/bytes.ts";
import { hexEncode } from "../src/core/bytes.ts";
import { hmacSha256 } from "../src/core/crypto.ts";

describe("github", () => {
  it("verifies the official GitHub docs vector", async () => {
    const result = await check({
      provider: "github",
      payload: GITHUB_OFFICIAL_VECTOR.payload,
      secret: GITHUB_OFFICIAL_VECTOR.secret,
      headers: { "X-Hub-Signature-256": GITHUB_OFFICIAL_VECTOR.header },
    });
    expect(result.status).toBe("verified");
    expect(result.verified).toBe(true);
    const mac = await hmacSha256(GITHUB_OFFICIAL_VECTOR.secret, GITHUB_OFFICIAL_VECTOR.payload);
    expect(hexEncode(mac)).toBe(GITHUB_OFFICIAL_VECTOR.hex);
  });

  it("accepts header names case-insensitively", async () => {
    const result = await check({
      provider: "github",
      payload: GITHUB_OFFICIAL_VECTOR.payload,
      secret: GITHUB_OFFICIAL_VECTOR.secret,
      headers: { "x-hub-signature-256": GITHUB_OFFICIAL_VECTOR.header },
    });
    expect(result.status).toBe("verified");
  });

  it("rejects a wrong secret", async () => {
    const result = await check({
      provider: "github",
      payload: GITHUB_OFFICIAL_VECTOR.payload,
      secret: "wrong-secret-not-the-real-one",
      headers: { "X-Hub-Signature-256": GITHUB_OFFICIAL_VECTOR.header },
    });
    expect(result.status).toBe("invalid");
    expect(result.secret?.provided).toBe(true);
    expect(result.secret?.length).toBe("wrong-secret-not-the-real-one".length);
    expect(result.secret?.fingerprint).toBe("f4a5fad5");
    expect(JSON.stringify(result)).not.toContain("wrong-secret-not-the-real-one");
  });

  it("identifies JSON re-stringify (pretty vs minify)", async () => {
    const min = '{"ok":true,"n":1}';
    const pretty = JSON.stringify(JSON.parse(min), null, 2);
    expect(pretty).not.toBe(min);
    const headers = await githubSign({ payload: utf8Encode(min), secret: "test_secret_github_json" });
    const result = await check({
      provider: "github",
      payload: utf8Encode(pretty),
      secret: "test_secret_github_json",
      headers,
    });
    expect(result.status).toBe("invalid");
    expect(result.diagnoses.some((d) => d.id === "json-minify")).toBe(true);
    const hit = result.diagnoses.find((d) => d.id === "json-minify");
    expect(hit?.confidence).toBe("high");
  });

  it("identifies a trailing newline", async () => {
    const body = "Hello, World!";
    const headers = await githubSign({ payload: utf8Encode(body), secret: "nl_secret" });
    const result = await check({
      provider: "github",
      payload: utf8Encode(`${body}\n`),
      secret: "nl_secret",
      headers,
    });
    expect(result.status).toBe("invalid");
    expect(result.diagnoses.some((d) => d.id === "trailing-lf")).toBe(true);
  });
});
