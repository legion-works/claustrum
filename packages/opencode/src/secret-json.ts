export class SecretJsonParseError extends Error {
  constructor(what: "auth file" | "handle file") {
    super(`${what} contains invalid JSON`);
    this.name = "SecretJsonParseError";
  }
}

export function parseSecretJson(text: string, what: "auth file" | "handle file"): unknown {
  try {
    return JSON.parse(text);
  } catch {
    throw new SecretJsonParseError(what);
  }
}
