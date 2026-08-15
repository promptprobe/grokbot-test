import { describe, expect, it } from "vitest";
import { EXIT_INVALID, EXIT_OK, EXIT_USAGE, run } from "../src/cli.ts";
import { captureIo, text } from "./helpers.ts";
import { check } from "../src/check.ts";
import { utf8Encode } from "../src/core/bytes.ts";

describe("cli", () => {
  it("generated vector fed back into check passes", async () => {
    const gen = captureIo();
    const genCode = await run(
      ["vector", "--provider", "github", "--json", "--secret", "cli_roundtrip_secret"],
      gen.io,
    );
    expect(genCode).toBe(EXIT_OK);
    const vector = JSON.parse(gen.stdout.join(""));
    const chk = captureIo(text(vector.payload), {});
    const headers = Object.entries(vector.headers as Record<string, string>).flatMap(
      ([name, value]) => ["--header", `${name}: ${value}`],
    );
    const code = await run(
      ["check", "--provider", "github", "--secret", vector.secret, "--json", ...headers],
      chk.io,
    );
    expect(code).toBe(EXIT_OK);
    const result = JSON.parse(chk.stdout.join(""));
    expect(result.status).toBe("verified");
  });

  it("check --json reports invalid without printing the secret", async () => {
    const io = captureIo(text("Hello, World!"));
    const secret = "super_secret_value_xyz";
    const code = await run(
      [
        "check",
        "--provider",
        "github",
        "--secret",
        secret,
        "--header",
        "X-Hub-Signature-256: sha256=0000000000000000000000000000000000000000000000000000000000000000",
        "--json",
      ],
      io.io,
    );
    expect(code).toBe(EXIT_INVALID);
    const dumped = io.stdout.join("") + io.stderr.join("");
    expect(dumped).not.toContain(secret);
    const parsed = JSON.parse(io.stdout.join(""));
    expect(parsed.status).toBe("invalid");
    expect(parsed.secret.last4).toBe("_xyz");
  });

  it("empty secret is a usage error and does not crash", async () => {
    const io = captureIo(text("body"));
    const code = await run(
      ["check", "--provider", "github", "--header", "X-Hub-Signature-256: sha256=ab"],
      io.io,
    );
    expect(code).toBe(EXIT_USAGE);
    expect(io.stdout.join("").toLowerCase()).toMatch(/secret/);
  });

  it("missing headers is a usage error", async () => {
    const io = captureIo(text("body"));
    const code = await run(["check", "--provider", "stripe", "--secret", "whsec_test"], io.io);
    expect(code).toBe(EXIT_USAGE);
    expect(io.stdout.join("")).toMatch(/Missing required header/);
  });

  it("reads payload-file and headers-file", async () => {
    const signed = await check({
      provider: "github",
      payload: utf8Encode("file-body"),
      secret: "file_secret_0001",
      headers: { "X-Hub-Signature-256": "sha256=00" },
    });
    expect(signed.status).not.toBe("verified");
    const { generateVector } = await import("../src/vector.ts");
    const vector = await generateVector({
      provider: "github",
      payload: utf8Encode("file-body"),
      secret: "file_secret_0001",
    });
    const cap = captureIo(new Uint8Array(), {
      "/tmp/payload.txt": utf8Encode("file-body"),
      "/tmp/headers.txt": utf8Encode(
        Object.entries(vector.headers)
          .map(([k, v]) => `${k}: ${v}`)
          .join("\n"),
      ),
    });
    const code = await run(
      [
        "check",
        "--provider",
        "github",
        "--secret",
        "file_secret_0001",
        "--payload-file",
        "/tmp/payload.txt",
        "--headers-file",
        "/tmp/headers.txt",
        "--json",
      ],
      cap.io,
    );
    expect(code).toBe(EXIT_OK);
  });

  it("unknown command is usage error", async () => {
    const io = captureIo();
    const code = await run(["nope"], io.io);
    expect(code).toBe(EXIT_USAGE);
  });

  it("vector requires provider", async () => {
    const io = captureIo();
    const code = await run(["vector"], io.io);
    expect(code).toBe(EXIT_USAGE);
  });
});
