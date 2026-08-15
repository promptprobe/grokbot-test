import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { utf8Encode } from "../src/core/bytes.ts";
import type { Io } from "../src/cli.ts";

export function text(s: string): Uint8Array {
  return utf8Encode(s);
}

export function captureIo(stdin: Uint8Array = new Uint8Array(), files: Record<string, Uint8Array> = {}) {
  const stdout: string[] = [];
  const stderr: string[] = [];
  const io: Io = {
    stdout: (t) => stdout.push(t),
    stderr: (t) => stderr.push(t),
    readStdin: async () => stdin,
    readFile: (path) => {
      const data = files[path];
      if (!data) throw new Error(`ENOENT: ${path}`);
      return data;
    },
  };
  return { io, stdout, stderr, files };
}

export function joined(parts: string[]): string {
  return parts.join("");
}

export function loadFixture<T>(name: string): T {
  const dir = join(dirname(fileURLToPath(import.meta.url)), "fixtures");
  return JSON.parse(readFileSync(join(dir, name), "utf8")) as T;
}
