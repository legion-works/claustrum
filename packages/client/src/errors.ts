export const ERROR_CLASS_WIRE_SET = [
  'transient',
  'permanent',
  'auth_required',
  'context_overflow',
] as const

export type ClaustrumCredentialErrorClass = (typeof ERROR_CLASS_WIRE_SET)[number]
export type ClaustrumCredentialErrorAction =
  | 'gone'
  | 'reauth'
  | 'retry'
  | 'reduce_and_retry'

export class ClaustrumCredentialError extends Error {
  readonly ['class']: ClaustrumCredentialErrorClass

  constructor(
    public readonly code: string,
    errorClass: ClaustrumCredentialErrorClass,
    public readonly action: ClaustrumCredentialErrorAction,
  ) {
    super(`Claustrum credential request failed: ${code}`)
    this.name = 'ClaustrumCredentialError'
    this['class'] = errorClass
  }
}

type UnknownClassLogger = (errorClass: string) => void

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

export function credentialErrorAction(
  errorClass: ClaustrumCredentialErrorClass,
): ClaustrumCredentialErrorAction {
  switch (errorClass) {
    case 'permanent':
      return 'gone'
    case 'auth_required':
      return 'reauth'
    case 'context_overflow':
      return 'reduce_and_retry'
    case 'transient':
      return 'retry'
  }
}

export function asCredentialError(
  response: unknown,
  fallbackCode = 'invalid_response',
  logUnknownClass: UnknownClassLogger = (errorClass) => console.warn(errorClass),
): ClaustrumCredentialError {
  const result = isRecord(response) && isRecord(response.result) ? response.result : undefined
  const error = result && isRecord(result.error) ? result.error : undefined
  const rawClass = error?.class
  const errorClass =
    typeof rawClass === 'string' && (ERROR_CLASS_WIRE_SET as readonly string[]).includes(rawClass)
      ? rawClass as ClaustrumCredentialErrorClass
      : 'transient'
  if (typeof rawClass !== 'string' || errorClass === 'transient' && rawClass !== 'transient') {
    logUnknownClass(typeof rawClass === 'string' ? rawClass : 'unknown')
  }
  const code = error && typeof error.code === 'string' ? error.code : fallbackCode
  return new ClaustrumCredentialError(code, errorClass, credentialErrorAction(errorClass))
}

export function hasCredentialError(response: unknown): boolean {
  return (
    isRecord(response) &&
    isRecord(response.result) &&
    isRecord(response.result.error)
  )
}
