import { appendFileSync, chmodSync, mkdirSync, renameSync, statSync } from "node:fs";
import { dirname, join } from "node:path";

import { identifierIsValid } from "@cortexkit/claustrum-client";

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
// A ≤24-character lowercase-snake residual such as sk_fake_secret shares the admitted code shape and is not all-hex.
export const ERROR_CLASS = /^(?:[A-Z][A-Za-z0-9]{0,47}|[a-z][a-z0-9_]{1,23})$/;
export const ERROR_CODE = /^(?:[A-Z][A-Z0-9_]{1,23}|[a-z][a-z0-9_]{1,23})$/;
// False positives to expect when diagnosing: an English word made only of hex letters (deadbeef, facade,
// decade) is rejected here and reaches the file as invalid_shape while looking ordinary at the call site.
// No current producer emits one — .name gives JS error names, .code gives errno strings — so a field that
// silently reads invalid_shape is the symptom to check first if a future producer starts emitting one.
export function isAllHexBody(value: string): boolean {
  return /^[0-9a-f]+$/i.test(value);
}
const LEVELS = new Set(["debug", "info", "warn", "error"]);
const ISO_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T[\d:.]+Z$/;
export const STATES = new Set([
  "available", "transient", "cooldown", "reauth", "other_owner", "orphan", "split", "unmanaged",
  "refusing", "serving", "served", "gone",
]);

// NOTHING ROUTINE GOES TO THE CONSOLE. The console is the OpenCode TUI's screen, and a
// plugin writing there corrupts the operator's terminal -- including mid-render, which is
// how this surfaced twice: first as info-level "serving" lines (2026-09-05), then as
// warn/error JSON printed over the TUI during a transient vault timeout (2026-09-11).
//
// The second one is the instructive one. The first fix kept faults on the console on the
// reasoning that "only faults belong there" -- a judgement substituted for the instruction,
// which was that ALL plugin logs go to the file. A fault is exactly when the plugin is
// noisiest, so the carve-out preserved the defect for the case that produces the most output.
//
// The console sink is gone. Every level goes to the file. The ONE remaining console write in
// this module is the once-per-process notice below, emitted only when the log FILE itself is
// unwritable -- reporting that logging is broken is not logging, and there is nowhere else to
// put it. If that line is ever seen in a terminal, the file sink has failed, which is the only
// condition under which this module may speak.

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
  // These pre-filter additions are process-generated ts/pid only; caller-influenced values enter through entry and their rules.
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
        case "provider": valid = identifierIsValid(value); break;
        // Import the parser's complete rule so the sink cannot accept a label the parser refuses.
        case "label": valid = identifierIsValid(value); break;
        case "credentialId": valid = CREDENTIAL_ID.test(value); break;
        case "state": valid = STATES.has(value); break;
        case "errorClass": valid = ERROR_CLASS.test(value) && !isAllHexBody(value); break;
        case "errorCode": valid = ERROR_CODE.test(value) && !isAllHexBody(value); break;
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
    // This notice is the ONLY thing this module prints, so it must describe the state it
    // actually leaves behind. It used to end "faults still reach the console", which was true
    // while a console sink carried warn/error -- deleting that sink made the sentence a lie in
    // the same commit, and an operator reading it would go looking for errors on a channel that
    // no longer carries any. Every level is dropped once the file is gone.
    warn("persistent custody log unavailable; ALL custody telemetry dropped, including warnings and errors");
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
  const output = sink ?? createFileLogSink();
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
