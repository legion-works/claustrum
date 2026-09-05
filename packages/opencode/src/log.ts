import { appendFileSync, chmodSync, mkdirSync, renameSync, statSync } from "node:fs";
import { dirname, join } from "node:path";

import { identifierIsValid } from "./handles";

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
  ts?: string;
  pid?: number;
};

export type LogSink = (entry: CustodyLogEntry) => void;

export type CustodyLogger = {
  debug(entry: Omit<CustodyLogEntry, "level">): void;
  info(entry: Omit<CustodyLogEntry, "level">): void;
  warn(entry: Omit<CustodyLogEntry, "level">): void;
  error(entry: Omit<CustodyLogEntry, "level">): void;
};

const FILE_LIMIT_BYTES = 5 * 1024 * 1024;
export const FILE_FIELDS: Array<keyof CustodyLogEntry> = [
  "level", "provider", "label", "credentialId", "recordVersion", "state", "httpStatus",
  "cooldownUntil", "errorClass", "errorCode", "ts", "pid",
];
const CREDENTIAL_ID = /^[A-Za-z0-9._:-]{1,128}$/;
const ERROR_CLASS = /^[A-Z][A-Za-z0-9]{0,47}$/;
const ERROR_CODE = /^(?:[A-Z][A-Z0-9_]{1,31}|[a-z][a-z0-9_]{1,31})$/;
const LEVELS = new Set(["debug", "info", "warn", "error"]);
const ISO_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T[\d:.]+Z$/;
export const STATES = new Set([
  "available", "transient", "cooldown", "reauth", "other_owner", "orphan", "split", "unmanaged",
  "refusing", "serving", "served", "gone",
]);

// Console is the OpenCode TUI's stdout: only faults belong there. Happy-path
// telemetry (info/debug) is file-only, or it becomes noise in the operator's screen.
function consoleSink(entry: CustodyLogEntry): void {
  if (entry.level !== "warn" && entry.level !== "error") return;
  console.error(JSON.stringify(entry));
}

export type FileLogSinkOptions = {
  path?: string;
  env?: NodeJS.ProcessEnv;
  warn?: (message: string) => void;
};

function defaultFilePath(env: NodeJS.ProcessEnv): string {
  const stateHome = env.XDG_STATE_HOME || (env.HOME ? join(env.HOME, ".local", "state") : ".local/state");
  return join(stateHome, "cortexkit", "opencode-plugin", "custody.jsonl");
}

function fileEntry(entry: CustodyLogEntry): Record<string, unknown> {
  const withMetadata = { ...entry, ts: new Date().toISOString(), pid: process.pid };
  const safe: Record<string, unknown> = {};
  for (const field of FILE_FIELDS) {
    if (withMetadata[field] !== undefined) {
      const value = withMetadata[field];
      if (typeof value !== "string") {
        safe[field] = (typeof value === "number" && Number.isFinite(value)) || typeof value === "boolean"
          ? value
          : "invalid_shape";
        continue;
      }
      let valid: boolean;
      switch (field) {
        case "level": valid = LEVELS.has(value); break;
        case "provider":
        case "label": valid = identifierIsValid(value); break;
        case "credentialId": valid = CREDENTIAL_ID.test(value); break;
        case "state": valid = STATES.has(value); break;
        case "errorClass": valid = ERROR_CLASS.test(value); break;
        case "errorCode": valid = ERROR_CODE.test(value); break;
        case "ts": valid = ISO_TIMESTAMP.test(value); break;
        default: valid = false;
      }
      safe[field] = valid ? value : "invalid_shape";
    }
  }
  return safe;
}

export function createFileLogSink(options: FileLogSinkOptions = {}): LogSink {
  const env = options.env ?? process.env;
  if (options.path === undefined && ["off", "0", "false", "no"].includes(env.CLAUSTRUM_CUSTODY_LOG ?? "")) {
    return () => {};
  }
  const path = options.path ?? env.CLAUSTRUM_CUSTODY_LOG ?? defaultFilePath(env);
  const warn = options.warn ?? ((message: string) => console.error(JSON.stringify({
    level: "warn",
    errorCode: "custody_log_unavailable",
    errorMessage: message,
  })));
  let unavailable = false;
  let initialized = false;
  const fail = () => {
    if (unavailable) return;
    unavailable = true;
    warn("persistent custody log unavailable; info/debug telemetry dropped, faults still reach the console");
  };
  const rotateIfNeeded = () => {
    try {
      if (statSync(path).size > FILE_LIMIT_BYTES) {
        renameSync(path, `${path}.1`);
        chmodSync(`${path}.1`, 0o600);
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
  };
  return (entry) => {
    if (unavailable) return;
    try {
      if (!initialized) {
        mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
        chmodSync(dirname(path), 0o700);
        rotateIfNeeded();
        initialized = true;
      }
      rotateIfNeeded();
      appendFileSync(path, `${JSON.stringify(fileEntry(entry))}\n`, { mode: 0o600 });
      chmodSync(path, 0o600);
    } catch {
      fail();
    }
  };
}

export function createLogger(sink?: LogSink): CustodyLogger {
  const fileSink = sink ? undefined : createFileLogSink();
  const output = sink ?? ((entry: CustodyLogEntry) => {
    consoleSink(entry);
    fileSink?.(entry);
  });
  return {
    debug: (entry) => output({ level: "debug", ...entry }),
    info: (entry) => output({ level: "info", ...entry }),
    warn: (entry) => output({ level: "warn", ...entry }),
    error: (entry) => output({ level: "error", ...entry }),
  };
}

export function serializedLogSink(write: (line: string) => void): LogSink {
  return (entry) => write(`${JSON.stringify(entry)}\n`);
}
