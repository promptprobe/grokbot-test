import type { CheckResult, Diagnosis } from "./core/types.ts";
import type { Vector } from "./core/types.ts";
import { vectorToCli } from "./vector.ts";

export function formatCheckHuman(result: CheckResult): string {
  const lines: string[] = [];
  if (result.status === "verified") {
    lines.push(`pass  verified  ${result.provider ?? ""}`.trimEnd());
  } else if (result.status === "error") {
    lines.push(`error  input  ${result.provider ?? ""}`.trimEnd());
  } else {
    lines.push(`fail  invalid  ${result.provider ?? ""}`.trimEnd());
  }
  lines.push(result.message);
  if (result.secret) {
    lines.push(`secret  length ${result.secret.length}, last4 ${result.secret.last4}`);
  }
  if (result.timestamp) {
    const skew = result.timestamp.skewSeconds;
    const flag = result.timestamp.withinTolerance ? "within tolerance" : "OUTSIDE tolerance";
    lines.push(
      `timestamp  ${result.timestamp.value}  skew ${skew}s  ${flag} (tol ${result.timestamp.toleranceSeconds}s)`,
    );
  }
  if (result.diagnoses.length) {
    lines.push("");
    lines.push("Likely causes (ranked):");
    result.diagnoses.forEach((d, i) => {
      lines.push(formatDiagnosis(d, i + 1));
    });
  } else if (result.status === "invalid") {
    lines.push("");
    lines.push(
      "No common payload/header mutation reproduced the signature. Check the secret, that you pasted the raw body (not re-encoded JSON), and that the header belongs to this request.",
    );
  }
  return lines.join("\n");
}

function formatDiagnosis(d: Diagnosis, index: number): string {
  return [
    `  ${index}. [${d.confidence}] ${d.title}`,
    `     ${d.detail}`,
  ].join("\n");
}

export function formatCheckJson(result: CheckResult): string {
  return `${JSON.stringify(result, jsonReplacer, 2)}\n`;
}

function jsonReplacer(_key: string, value: unknown): unknown {
  if (value instanceof Uint8Array) {
    return { encoding: "hex", length: value.length };
  }
  return value;
}

export function formatVectorHuman(vector: Vector): string {
  const headerLines = Object.entries(vector.headers)
    .map(([k, v]) => `  ${k}: ${v}`)
    .join("\n");
  return [
    `provider  ${vector.provider}`,
    `secret    ${vector.secret}`,
    `payload   (${vector.payloadEncoding})`,
    vector.payload,
    "",
    "headers",
    headerLines,
    "",
    vector.notes ?? "",
    "",
    "CLI",
    vectorToCli(vector),
  ].join("\n");
}

export function formatVectorJson(vector: Vector): string {
  return `${JSON.stringify(vector, null, 2)}\n`;
}
