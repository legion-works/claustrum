# @cortexkit/claustrum-client

Policy-free TypeScript transport for the Claustrum credential vault. Consumers own
credential caching, refresh, account scheduling, and retry policy.

## Wire contract callers depend on

• The daemon records a durable anomaly alarm after 64 fetches in 60 seconds or
  16 distinct handles on one connection. It still serves those requests. Timed-out
  gets count, and the detector resets on reconnect. Use one warm attempt per
  account per tick and apply per-handle backoff after transient failures.
• `credential.get` is bimodal: resident records return in microseconds, while an
  expiry-skew refresh can take seconds. Request paths should peek cached state,
  not call `get` speculatively.
• `permanent` with `not_found` means the handle is unknown OR revoked — uniform refusal
  by design (the vault cannot enumerate which). Treat it as gone either way: re-run
  `ck auth migrate-opencode` to mint a fresh handle; the prior record, if any, is kept.
• `auth_required` means the record is latched and needs reauthentication.
• Unknown server error classes are bounded to `transient`; callers must retry them
  rather than treating a forward-compatible class as permanent.

The client sends `consumerIdentity: null` for every managed request so inherited
`SUBC_MODULE_ID` and `SUBC_LAUNCH_NONCE` cannot impersonate a supervising host.

## OpenCode handle-file exports

`defaultHandleFilePath`, `readHandleFile`, `handleFileRevision`, and `parseHandleFile`
are exported for tenant plugins consuming the OpenCode handle manifest. The shared
`HANDLE_FILE_CONTRACT` is pinned to `maxBytes: 262144`, `mode: 0o600`,
`labelRe: /^[a-z0-9][a-z0-9._-]{0,63}$/`, and
`handleRe: /^ckh_[A-Za-z0-9_-]{43}$/`. Readers require a regular uid-owned file,
an owned non-world-writable parent, and reject prototype keys.
