export class HandleFileValidationError extends Error {
  override name = "HandleFileValidationError";
}

export class CustodySplitError extends Error {
  override name = "CustodySplitError";
}

export class CustodyOrphanError extends Error {
  override name = "CustodyOrphanError";
}
