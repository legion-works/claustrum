export class ConnectionJsonParseError extends Error {
  constructor() {
    super('connection file is not valid JSON')
    this.name = 'ConnectionJsonParseError'
  }
}

export function parseSecretJson(text: string): unknown {
  try {
    return JSON.parse(text)
  } catch {
    throw new ConnectionJsonParseError()
  }
}
