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
• `permanent` with `not_found` means the handle was revoked.
• `auth_required` means the record is latched and needs reauthentication.
• Unknown server error classes are bounded to `transient`; callers must retry them
  rather than treating a forward-compatible class as permanent.

The client sends `consumerIdentity: null` for every managed request so inherited
`SUBC_MODULE_ID` and `SUBC_LAUNCH_NONCE` cannot impersonate a supervising host.
