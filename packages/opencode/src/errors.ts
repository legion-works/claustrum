export class HandleFileValidationError extends Error {
  override name = "HandleFileValidationError";
}

export class AuthFileValidationError extends Error {
  override name = "AuthFileValidationError";
}

export class CustodyRedirectRefusedError extends Error {
  override name = "CustodyRedirectRefusedError";

  constructor(provider: string, fromOrigin: string, toOrigin: string) {
    super(`custody redirect refused: provider=${provider} from=${fromOrigin} to=${toOrigin}`);
  }
}

export class CustodySplitError extends Error {
  override name = "CustodySplitError";
}

export class CustodyOrphanError extends Error {
  override name = "CustodyOrphanError";
}

export class CustodyOwnershipError extends Error {
  override name = "CustodyOwnershipError";
}

export class CustodyAuthReadError extends Error {
  override name = "CustodyAuthReadError";
}

export class CustodyRequestError extends Error {
  override name = "CustodyRequestError";

  // Structured discriminators so callers can branch on the cause without parsing
  // `message`. The message itself is rendered by the serve path using `error.name`
  // only (`cause` is intentionally NOT propagated into the log line nor into the
  // thrown wrapper's message), so anything an upstream fetcher or a substituted URL
  // might leak stays out of operator-facing logs.
  readonly code?: string;
  readonly cause?: unknown;

  constructor(message: string, options?: { code?: string; cause?: unknown }) {
    super(message);
    if (options?.code !== undefined) this.code = options.code;
    if (options?.cause !== undefined) this.cause = options.cause;
  }
}

export class CustodyNativeRuntimeError extends Error {
  override name = "CustodyNativeRuntimeError";
}

export class CustodyExhaustionError extends Error {
  override name = "CustodyExhaustionError";
}

export type CustodyAccountSnapshot = {
  label: string;
  state: string;
  warmTimedOut: boolean;
};

// A budget miss is retryable and the next warm succeeds, so a caller branching on exhaustion must not catch it.
export class CustodyWarmTimeoutError extends Error {
  override name = "CustodyWarmTimeoutError";
  readonly reason = "warm_timeout" as const;
  readonly accountStates: readonly CustodyAccountSnapshot[];

  constructor(message: string, accountStates: readonly CustodyAccountSnapshot[]) {
    super(message);
    this.accountStates = accountStates;
  }
}

export class ReportedCustodyExhaustionError extends CustodyExhaustionError {
  readonly reason = "exhausted" as const;
  readonly adviseMigrate: boolean;
  readonly accountStates: readonly CustodyAccountSnapshot[];

  constructor(message: string, accountStates: readonly CustodyAccountSnapshot[], adviseMigrate: boolean) {
    super(message);
    this.adviseMigrate = adviseMigrate;
    this.accountStates = accountStates;
  }
}
