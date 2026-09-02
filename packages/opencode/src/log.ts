export type LogLevel = "debug" | "info" | "warn" | "error";

export type CustodyLogEntry = {
  level: LogLevel;
  provider?: string;
  label?: string;
  credentialId?: string;
  recordVersion?: number;
  state?: string;
  httpStatus?: number;
  cooldownUntil?: number;
  errorClass?: string;
  errorCode?: string;
  errorMessage?: string;
};

export type LogSink = (entry: CustodyLogEntry) => void;

export type CustodyLogger = {
  debug(entry: Omit<CustodyLogEntry, "level">): void;
  info(entry: Omit<CustodyLogEntry, "level">): void;
  warn(entry: Omit<CustodyLogEntry, "level">): void;
  error(entry: Omit<CustodyLogEntry, "level">): void;
};

// Default sink writes each level to the stream a maintainer looks at for that level:
// debug / info to stdout, warn / error to stderr. The previous implementation routed
// everything to `console.error`, which made the `level` field a label rather than a
// semantic switch -- `console.debug` against a release binary that has stripped debug
// is the lever operators use to silence a noisy daemon, and routing those records to
// stderr defeats the lever.
function defaultSink(entry: CustodyLogEntry): void {
  const out = entry.level === "warn" || entry.level === "error" ? console.error : console.log;
  out(JSON.stringify(entry));
}

export function createLogger(sink: LogSink = defaultSink): CustodyLogger {
  return {
    debug: (entry) => sink({ level: "debug", ...entry }),
    info: (entry) => sink({ level: "info", ...entry }),
    warn: (entry) => sink({ level: "warn", ...entry }),
    error: (entry) => sink({ level: "error", ...entry }),
  };
}

export function serializedLogSink(write: (line: string) => void): LogSink {
  return (entry) => write(`${JSON.stringify(entry)}\n`);
}
