export type ProviderId = "github" | "stripe" | "slack" | "standard";

export type Confidence = "high" | "medium" | "low";

export type CheckStatus = "verified" | "invalid" | "error";

export interface Diagnosis {
  id: string;
  rank: number;
  title: string;
  detail: string;
  confidence: Confidence;
}

export interface SecretHint {
  length: number;
  last4: string;
}

export interface TimestampInfo {
  value: number;
  skewSeconds: number;
  withinTolerance: boolean;
  toleranceSeconds: number;
}

export interface CheckInput {
  provider?: ProviderId;
  payload: Uint8Array;
  secret: string;
  headers: Record<string, string>;
  now?: number;
  toleranceSeconds?: number;
}

export interface CheckResult {
  status: CheckStatus;
  provider?: ProviderId;
  verified: boolean;
  message: string;
  diagnoses: Diagnosis[];
  secret?: SecretHint;
  timestamp?: TimestampInfo;
}

export interface VerifyInput {
  payload: Uint8Array;
  secret: string;
  headers: Record<string, string>;
  now: number;
  toleranceSeconds: number;
}

export interface VerifyOutcome {
  ok: boolean;
  hmacMatch: boolean;
  reason?: string;
  timestamp?: TimestampInfo;
  missingHeaders?: string[];
}

export interface SignInput {
  payload: Uint8Array;
  secret: string;
  timestamp?: number;
  id?: string;
}

export interface Vector {
  provider: ProviderId;
  payload: string;
  payloadEncoding: "utf8" | "base64";
  secret: string;
  headers: Record<string, string>;
  notes?: string;
}

export interface Hypothesis {
  id: string;
  rank: number;
  title: string;
  detail: string;
  confidence: Confidence;
  payload?: Uint8Array;
  secret?: string;
  headers?: Record<string, string>;
  ignoreTolerance?: boolean;
  scheme?: string;
}

export const DEFAULT_TOLERANCE_SECONDS = 300;
