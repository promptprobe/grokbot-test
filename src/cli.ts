#!/usr/bin/env node
import { parseArgs } from "node:util";
import { readFileSync } from "node:fs";
import { stdin as stdinStream } from "node:process";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
import { check } from "./check.ts";
import { isProviderId } from "./providers/index.ts";
import { parseHeaderLines, parseSingleHeader } from "./core/headers.ts";
import {
  formatCheckHuman,
  formatCheckJson,
  formatVectorHuman,
  formatVectorJson,
} from "./format.ts";
import { generateVector } from "./vector.ts";
import type { ProviderId } from "./core/types.ts";
import { startServer } from "./serve.ts";

export const EXIT_OK = 0;
export const EXIT_INVALID = 1;
export const EXIT_USAGE = 2;

export interface Io {
  stdout: (text: string) => void;
  stderr: (text: string) => void;
  readStdin: () => Promise<Uint8Array>;
  readFile: (path: string) => Uint8Array;
}

const defaultIo: Io = {
  stdout: (text) => {
    process.stdout.write(text.endsWith("\n") ? text : `${text}\n`);
  },
  stderr: (text) => {
    process.stderr.write(text.endsWith("\n") ? text : `${text}\n`);
  },
  readStdin: () => {
    if (stdinStream.isTTY) {
      return Promise.reject(
        new Error("Provide --payload-file PATH or pipe the raw body on stdin"),
      );
    }
    return readStdinBytes();
  },
  readFile: (path) => new Uint8Array(readFileSync(path)),
};

const USAGE = `whyhook — local-first webhook signature debugger

Usage:
  whyhook check [options]
  whyhook vector [options]
  whyhook serve [--port 8787]
  whyhook --help

check options:
  --provider, -p     github | stripe | slack | standard
  --secret, -s       signing secret (never logged)
  --secret-file      read secret from file (trailing newline stripped)
  --header, -H       "Name: value" (repeatable)
  --headers-file     JSON object or HTTP-style header lines
  --payload-file     raw body file; "-" or omit reads stdin
  --json             machine-readable result
  --tolerance        timestamp tolerance in seconds (default 300)
  --now              unix seconds (testing)

vector options:
  --provider, -p     required
  --secret, -s       optional fake secret
  --payload-file     optional body
  --json
  --timestamp        unix seconds
  --id               webhook-id (standard)

Exit codes: 0 verified, 1 invalid, 2 usage/input error

Secrets never leave this machine. Reports print length + last4 only.
`;

function stripNodeInvocation(argv: string[]): string[] {
  const bin = argv[0] ?? "";
  if (bin.endsWith("node") || bin.endsWith("node.exe") || bin.endsWith("nodejs")) {
    return argv.slice(2);
  }
  return argv;
}

export async function run(argv: string[], io: Io = defaultIo): Promise<number> {
  const args = stripNodeInvocation(argv);
  const command = args[0];
  if (
    command === undefined ||
    command === "-h" ||
    command === "--help" ||
    command === "help"
  ) {
    io.stdout(USAGE);
    return command === undefined ? EXIT_USAGE : EXIT_OK;
  }
  if (command === "-v" || command === "--version" || command === "version") {
    io.stdout("whyhook 0.1.0");
    return EXIT_OK;
  }
  try {
    if (command === "check") return await runCheck(args.slice(1), io);
    if (command === "vector") return await runVector(args.slice(1), io);
    if (command === "serve") return await runServe(args.slice(1), io);
    io.stderr(`Unknown command "${command}". Try whyhook --help.`);
    return EXIT_USAGE;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    io.stderr(`error: ${message}`);
    return EXIT_USAGE;
  }
}

async function runCheck(argv: string[], io: Io): Promise<number> {
  const parsed = parseArgs({
    args: argv,
    options: {
      provider: { type: "string", short: "p" },
      secret: { type: "string", short: "s" },
      "secret-file": { type: "string" },
      header: { type: "string", short: "H", multiple: true },
      "headers-file": { type: "string" },
      "payload-file": { type: "string" },
      json: { type: "boolean", default: false },
      tolerance: { type: "string" },
      now: { type: "string" },
      help: { type: "boolean", short: "h", default: false },
    },
    allowPositionals: false,
    strict: true,
  });
  if (parsed.values.help) {
    io.stdout(USAGE);
    return EXIT_OK;
  }
  const headers: Record<string, string> = {};
  if (parsed.values["headers-file"]) {
    const bytes = io.readFile(parsed.values["headers-file"]);
    Object.assign(headers, parseHeaderLines(new TextDecoder().decode(bytes)));
  }
  for (const raw of parsed.values.header ?? []) {
    const { name, value } = parseSingleHeader(raw);
    headers[name] = value;
  }
  let secret = parsed.values.secret ?? "";
  if (parsed.values["secret-file"]) {
    const text = new TextDecoder().decode(io.readFile(parsed.values["secret-file"]));
    secret = text.replace(/(?:\r?\n)+$/u, "");
  }
  const payload = await readPayload(parsed.values["payload-file"], io);
  const tolerance = parsed.values.tolerance
    ? Number.parseInt(parsed.values.tolerance, 10)
    : undefined;
  const now = parsed.values.now ? Number.parseInt(parsed.values.now, 10) : undefined;
  if (parsed.values.tolerance && !Number.isFinite(tolerance)) {
    throw new Error("--tolerance must be an integer number of seconds");
  }
  if (parsed.values.now && !Number.isFinite(now)) {
    throw new Error("--now must be unix seconds");
  }
  const result = await check({
    provider: parsed.values.provider as ProviderId | undefined,
    payload,
    secret,
    headers,
    toleranceSeconds: tolerance,
    now,
  });
  const text = parsed.values.json ? formatCheckJson(result) : formatCheckHuman(result);
  if (secret && text.includes(secret) && result.status !== "verified") {
    // vector-style reports never go through check; still guard
  }
  if (secret && !parsed.values.json && text.includes(secret)) {
    io.stderr("error: refused to print a report that contained the secret");
    return EXIT_USAGE;
  }
  io.stdout(text);
  if (result.status === "verified") return EXIT_OK;
  if (result.status === "error") return EXIT_USAGE;
  return EXIT_INVALID;
}

async function runVector(argv: string[], io: Io): Promise<number> {
  const parsed = parseArgs({
    args: argv,
    options: {
      provider: { type: "string", short: "p" },
      secret: { type: "string", short: "s" },
      "payload-file": { type: "string" },
      json: { type: "boolean", default: false },
      timestamp: { type: "string" },
      id: { type: "string" },
      help: { type: "boolean", short: "h", default: false },
    },
    allowPositionals: false,
    strict: true,
  });
  if (parsed.values.help) {
    io.stdout(USAGE);
    return EXIT_OK;
  }
  const provider = parsed.values.provider;
  if (!provider || !isProviderId(provider)) {
    throw new Error("--provider is required (github|stripe|slack|standard)");
  }
  let payload: Uint8Array | undefined;
  if (parsed.values["payload-file"]) {
    payload = await readPayload(parsed.values["payload-file"], io);
  }
  const timestamp = parsed.values.timestamp
    ? Number.parseInt(parsed.values.timestamp, 10)
    : undefined;
  if (parsed.values.timestamp && !Number.isFinite(timestamp)) {
    throw new Error("--timestamp must be unix seconds");
  }
  const vector = await generateVector({
    provider,
    payload,
    secret: parsed.values.secret,
    timestamp,
    id: parsed.values.id,
  });
  io.stdout(parsed.values.json ? formatVectorJson(vector) : formatVectorHuman(vector));
  return EXIT_OK;
}

async function runServe(argv: string[], io: Io): Promise<number> {
  const parsed = parseArgs({
    args: argv,
    options: {
      port: { type: "string" },
      help: { type: "boolean", short: "h", default: false },
    },
    allowPositionals: false,
    strict: true,
  });
  if (parsed.values.help) {
    io.stdout(USAGE);
    return EXIT_OK;
  }
  const port = parsed.values.port ? Number.parseInt(parsed.values.port, 10) : 8787;
  if (!Number.isFinite(port) || port < 1 || port > 65535) {
    throw new Error("--port must be 1–65535");
  }
  const running = await startServer({ port, log: (msg) => io.stdout(msg) });
  await new Promise((resolveWait) => {
    const stop = () => {
      running.close().finally(() => resolveWait(undefined));
    };
    process.on("SIGINT", stop);
    process.on("SIGTERM", stop);
  });
  return EXIT_OK;
}

async function readPayload(payloadFile: string | undefined, io: Io): Promise<Uint8Array> {
  if (payloadFile && payloadFile !== "-") {
    return io.readFile(payloadFile);
  }
  const bytes = await io.readStdin();
  return bytes;
}

function readStdinBytes(): Promise<Uint8Array> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    stdinStream.on("data", (chunk: Buffer | string) => {
      chunks.push(typeof chunk === "string" ? Buffer.from(chunk) : chunk);
    });
    stdinStream.on("end", () => resolve(new Uint8Array(Buffer.concat(chunks))));
    stdinStream.on("error", reject);
    if (stdinStream.readableEnded) {
      resolve(new Uint8Array(Buffer.concat(chunks)));
    }
  });
}

function invokedAsCli(): boolean {
  const arg = process.argv[1];
  if (!arg) return false;
  try {
    return fileURLToPath(import.meta.url) === resolve(arg);
  } catch {
    return false;
  }
}
const isMain = invokedAsCli();

if (isMain) {
  run(process.argv).then(
    (code) => {
      process.exitCode = code;
    },
    (err) => {
      console.error(err instanceof Error ? err.message : err);
      process.exitCode = EXIT_USAGE;
    },
  );
}
