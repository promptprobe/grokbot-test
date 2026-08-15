# whyhook

Local-first webhook signature debugger.

Paste a raw HTTP body, the signature headers, and the signing secret. whyhook verifies GitHub, Stripe, Slack, and Standard Webhooks HMAC signatures on your machine, then ranks the usual reasons verification failed: JSON re-serialized after JSON.parse, a trailing newline, hex vs base64, a missing sha256= / v0= prefix, Stripe signing the raw body instead of t.payload, or a timestamp outside the replay window.

Nothing is sent off-machine. Secrets are never logged. Reports show that a secret was provided, its length, and a short SHA-256 fingerprint (8 hex chars). Never the raw secret.

## Who it is for

Backend engineers implementing webhook receivers who just got "invalid signature" and need to know which transformation would make the HMAC match.

## Install

Requires Node.js 22+.

```
git clone https://github.com/promptprobe/grokbot-test.git
cd grokbot-test
npm install
npm run build
node dist/cli.js --help
```

Until the package is published, use `node dist/cli.js` or `npm run whyhook --`.

## Usage

Exit codes: 0 verified, 1 invalid signature, 2 usage or input error.

### Check a delivery

Recommended: pass the signing secret with `--secret-file` so it does not appear on the command line.

```
printf 'Hello, World!' > /tmp/body.txt
node dist/cli.js check --provider github --secret-file ./secret.txt --header "X-Hub-Signature-256: sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17" --payload-file /tmp/body.txt
```

`--secret` is convenience/testing only (for example the public GitHub docs vector `It's a Secret to Everybody`):

```
printf 'Hello, World!' > /tmp/body.txt
node dist/cli.js check --provider github --secret "It's a Secret to Everybody" --header "X-Hub-Signature-256: sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17" --payload-file /tmp/body.txt
```

Machine-readable:

```
node dist/cli.js check --json --provider stripe --secret-file ./secret.txt --headers-file ./headers.txt --payload-file ./body.json
```

`--headers-file` accepts HTTP-style header lines or a JSON object. Header names are case-insensitive. Pipe the raw body on stdin if you omit `--payload-file`. `--tolerance` sets the timestamp window in seconds (default 300). `--now` overrides the clock (unix seconds) for tests.

### Generate a fixture

```
node dist/cli.js vector --provider slack --json
```

A generated vector can be fed back into `check` and should verify.

### Local UI

```
node dist/cli.js serve
node dist/cli.js serve --port 8899
```

The server binds 127.0.0.1 only and serves static files. Verification runs in the browser with Web Crypto. The secret is not posted to the local server. Dev UI: `npm run dev:ui`.

## Architecture

- src/core/ — bytes, hex/base64, timing-safe compare, HMAC via Node crypto / Web Crypto
- src/providers/ — GitHub, Stripe, Slack, Standard Webhooks verify + detect
- src/diagnose.ts — ranked hypotheses
- src/check.ts — validate, verify, diagnose
- src/cli.ts — check, vector, serve
- src/web/ — Vite UI using the same check() path

No database. No environment variables. No network calls during verify.

Provider schemes:
- GitHub: HMAC-SHA256 of the raw body. Header X-Hub-Signature-256: sha256=<hex>
- Stripe: HMAC-SHA256 of `${t}.${rawBody}`. Header Stripe-Signature: t=<unix>,v1=<hex>. Extra v0= keys ignored. 5-minute window.
- Slack: HMAC-SHA256 of `v0:${timestamp}:${body}`. Headers X-Slack-Request-Timestamp and X-Slack-Signature: v0=<hex>
- Standard Webhooks: HMAC-SHA256 of `msg_id.timestamp.payload`. Headers webhook-id, webhook-timestamp, webhook-signature (v1,<base64>, space-delimited). Secret is whsec_ plus base64 key bytes.

## Environment variables

None. Do not put signing secrets in .env files checked into git. Pass `--secret-file` (recommended) or `--secret` (convenience/testing only), or type the secret in the local UI.

## Testing

Run locally:

```
npm test
npm run typecheck
npm run lint
npm run build
```

A GitHub Actions workflow exists in the working tree at `.github/workflows/ci.yml` but could not be pushed because the GitHub token lacks the `workflow` scope. CI is not running on this GitHub repository.

## Security

Timing-safe compare on the real verify path. Local serve binds loopback only. Reports refuse to print if they would contain the raw secret. This is a debugger, not a replacement for a production verifier library.

## Known limitations

- Standard Webhooks Ed25519 v1a is not implemented
- Timestamp skew uses the local clock (or --now)
- GitHub legacy X-Hub-Signature (SHA-1) is not verified
- Auto-detect needs the vendor header names; pass --provider when they are missing
- Not a hosted service and not a substitute for official SDKs in production

## License

Apache-2.0
