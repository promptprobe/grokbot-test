import { check } from "../check.ts";
import { parseHeaderLines } from "../core/headers.ts";
import { utf8Encode } from "../core/bytes.ts";
import { generateVector } from "../vector.ts";
import type { CheckResult, ProviderId } from "../core/types.ts";

const form = document.querySelector<HTMLFormElement>("#form")!;
const payloadEl = document.querySelector<HTMLTextAreaElement>("#payload")!;
const headersEl = document.querySelector<HTMLTextAreaElement>("#headers")!;
const secretEl = document.querySelector<HTMLInputElement>("#secret")!;
const statusEl = document.querySelector<HTMLDivElement>("#status")!;
const metaEl = document.querySelector<HTMLDivElement>("#meta")!;
const diagnosesEl = document.querySelector<HTMLOListElement>("#diagnoses")!;
const copyBtn = document.querySelector<HTMLButtonElement>("#copy-vector")!;
const toggleSecret = document.querySelector<HTMLButtonElement>("#toggle-secret")!;
const fillBtn = document.querySelector<HTMLButtonElement>("#fill-vector")!;

let lastResult: CheckResult | null = null;
let lastHeaders: Record<string, string> = {};

function selectedProvider(): ProviderId {
  const checked = form.querySelector<HTMLInputElement>('input[name="provider"]:checked');
  return (checked?.value as ProviderId) ?? "github";
}

function setStatus(kind: "empty" | "pass" | "fail" | "error", title: string, detail: string, kicker: string) {
  statusEl.className = `status ${kind}`;
  statusEl.innerHTML = "";
  const k = document.createElement("p");
  k.className = "status-kicker";
  k.textContent = kicker;
  const t = document.createElement("p");
  t.className = "status-title";
  t.textContent = title;
  const d = document.createElement("p");
  d.className = "status-detail";
  d.textContent = detail;
  statusEl.append(k, t, d);
}

toggleSecret.addEventListener("click", () => {
  const show = secretEl.type === "password";
  secretEl.type = show ? "text" : "password";
  toggleSecret.textContent = show ? "Hide" : "Show";
  toggleSecret.setAttribute("aria-pressed", show ? "true" : "false");
});

form.addEventListener("reset", () => {
  queueMicrotask(() => {
    lastResult = null;
    copyBtn.disabled = true;
    metaEl.hidden = true;
    diagnosesEl.hidden = true;
    diagnosesEl.replaceChildren();
    setStatus(
      "empty",
      "Paste a body, headers, and secret.",
      "Verification runs entirely in this page with Web Crypto. Nothing is posted to the local server.",
      "empty",
    );
  });
});

fillBtn.addEventListener("click", async () => {
  const vector = await generateVector({ provider: selectedProvider() });
  payloadEl.value = vector.payloadEncoding === "utf8" ? vector.payload : vector.payload;
  headersEl.value = Object.entries(vector.headers)
    .map(([k, v]) => `${k}: ${v}`)
    .join("\n");
  secretEl.value = vector.secret;
  await runVerify();
});

copyBtn.addEventListener("click", async () => {
  if (!lastResult) return;
  const vector = {
    provider: lastResult.provider,
    payload: payloadEl.value,
    secret: secretEl.value,
    headers: lastHeaders,
    verified: lastResult.verified,
    diagnoses: lastResult.diagnoses,
  };
  const text = JSON.stringify(vector, null, 2);
  try {
    await navigator.clipboard.writeText(text);
    copyBtn.textContent = "Copied";
    setTimeout(() => {
      copyBtn.textContent = "Copy as vector";
    }, 1200);
  } catch {
    copyBtn.textContent = "Copy failed";
  }
});

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  await runVerify();
});

async function runVerify(): Promise<void> {
  let headers: Record<string, string> = {};
  try {
    headers = parseHeaderLines(headersEl.value);
  } catch (err) {
    lastResult = null;
    copyBtn.disabled = true;
    metaEl.hidden = true;
    diagnosesEl.hidden = true;
    setStatus(
      "error",
      "Could not parse headers",
      err instanceof Error ? err.message : String(err),
      "error",
    );
    return;
  }
  lastHeaders = headers;
  const result = await check({
    provider: selectedProvider(),
    payload: utf8Encode(payloadEl.value),
    secret: secretEl.value,
    headers,
  });
  lastResult = result;
  copyBtn.disabled = false;
  renderResult(result);
}

function renderResult(result: CheckResult): void {
  if (result.status === "verified") {
    setStatus("pass", "Verified", result.message, "pass");
  } else if (result.status === "error") {
    setStatus("error", "Input error", result.message, "error");
  } else {
    setStatus("fail", "Invalid signature", result.message, "fail");
  }
  const bits: string[] = [];
  if (result.provider) bits.push(`provider ${result.provider}`);
  if (result.secret) bits.push(`secret provided, length ${result.secret.length}, fingerprint ${result.secret.fingerprint}`);
  if (result.timestamp) {
    bits.push(
      `ts ${result.timestamp.value} · skew ${result.timestamp.skewSeconds}s · tol ${result.timestamp.toleranceSeconds}s`,
    );
  }
  if (bits.length) {
    metaEl.hidden = false;
    metaEl.replaceChildren();
    for (const line of bits) {
      const p = document.createElement("div");
      p.textContent = line;
      metaEl.append(p);
    }
  } else {
    metaEl.hidden = true;
  }
  if (result.diagnoses.length) {
    diagnosesEl.hidden = false;
    diagnosesEl.replaceChildren();
    result.diagnoses.forEach((d, i) => {
      const li = document.createElement("li");
      const top = document.createElement("div");
      top.className = "diag-top";
      const rank = document.createElement("span");
      rank.className = "diag-rank";
      rank.textContent = `Hit ${i + 1}`;
      const badge = document.createElement("span");
      badge.className = `badge ${d.confidence}`;
      badge.textContent = d.confidence;
      top.append(rank, badge);
      const title = document.createElement("p");
      title.className = "diag-title";
      title.textContent = d.title;
      const detail = document.createElement("p");
      detail.className = "diag-detail";
      detail.textContent = d.detail;
      li.append(top, title, detail);
      diagnosesEl.append(li);
    });
  } else {
    diagnosesEl.hidden = true;
    diagnosesEl.replaceChildren();
  }
}
