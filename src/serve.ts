import { createServer } from "node:http";
import { existsSync, statSync, createReadStream } from "node:fs";
import { dirname, extname, join, normalize, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const BIND_HOST = "127.0.0.1";

const TYPES: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".map": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".txt": "text/plain; charset=utf-8",
};

export type ServeOptions = {
  port: number;
  log?: (message: string) => void;
  webRoot?: string;
};

export type RunningServer = {
  port: number;
  host: string;
  url: string;
  close: () => Promise<void>;
};

function findWebRoot(explicit?: string): string {
  if (explicit) return explicit;
  const here = dirname(fileURLToPath(import.meta.url));
  const candidates = [join(here, "web"), join(here, "../dist/web"), join(process.cwd(), "dist/web")];
  for (const dir of candidates) {
    if (existsSync(join(dir, "index.html"))) return dir;
  }
  throw new Error("UI build not found (dist/web/index.html). Run the build script first.");
}

export function startServer(options: ServeOptions): Promise<RunningServer> {
  const webRoot = findWebRoot(options.webRoot);
  const server = createServer((req, res) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Cache-Control", "no-store");
    res.setHeader(
      "Content-Security-Policy",
      "default-src 'self'; connect-src 'none'; form-action 'none'; frame-ancestors 'none'; base-uri 'self'",
    );
    const method = req.method ?? "GET";
    if (method !== "GET" && method !== "HEAD") {
      res.statusCode = 405;
      res.end("method not allowed");
      return;
    }
    let rel = "/index.html";
    try {
      rel = new URL(req.url ?? "/", "http://127.0.0.1").pathname;
      rel = decodeURIComponent(rel);
    } catch {
      res.statusCode = 400;
      res.end("bad request");
      return;
    }
    if (rel === "/") rel = "/index.html";
    const cleaned = normalize(rel).replace(/^(\.\.(\/|\\|$))+/, "");
    const filePath = join(webRoot, cleaned);
    if (!filePath.startsWith(resolve(webRoot))) {
      res.statusCode = 403;
      res.end("forbidden");
      return;
    }
    if (!existsSync(filePath) || statSync(filePath).isDirectory()) {
      res.statusCode = 404;
      res.end("not found");
      return;
    }
    const type = TYPES[extname(filePath).toLowerCase()] ?? "application/octet-stream";
    res.setHeader("Content-Type", type);
    if (method === "HEAD") {
      res.end();
      return;
    }
    createReadStream(filePath).pipe(res);
  });
  return new Promise((resolvePromise, reject) => {
    server.on("error", reject);
    server.listen(options.port, BIND_HOST, () => {
      const url = "http://127.0.0.1:" + String(options.port);
      options.log?.("whyhook UI on " + url + " (loopback only; verification runs in the browser)");
      resolvePromise({
        port: options.port,
        host: BIND_HOST,
        url,
        close: () =>
          new Promise((res, rej) => {
            server.close((err) => (err ? rej(err) : res()));
          }),
      });
    });
  });
}
