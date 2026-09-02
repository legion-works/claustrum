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
}

export class CustodyNativeRuntimeError extends Error {
  override name = "CustodyNativeRuntimeError";
}

export class CustodyExhaustionError extends Error {
  override name = "CustodyExhaustionError";
}
