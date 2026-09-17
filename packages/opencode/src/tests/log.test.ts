import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  createFileLogSink,
  createLogger,
  ERROR_CLASS,
  ERROR_CODE,
  FILE_FIELDS,
  isAllHexBody,
  serializedLogSink,
  STATES,
} from "../log";

describe("custody logger", () => {
  // EVERY console channel the module could reach must be captured, not just the ones it uses
  // today. Capturing a subset silently narrows every "nothing reached the console" assertion in
  // this file to "nothing reached the channels I happened to mock" -- and console.warn was the
  // gap: a fallback written via console.warn passed all 16 tests, including the one whose whole
  // purpose is to deny console output. Found by review, after a mutation of mine used
  // console.error and cleared the only channel that was covered.
  const originalDebug = console.debug;
  const originalLog = console.log;
  const originalError = console.error;
  const originalWarn = console.warn;
  let debugLines: string[];
  let logLines: string[];
  let errorLines: string[];
  let warnLines: string[];

  beforeEach(() => {
    debugLines = [];
    logLines = [];
    errorLines = [];
    warnLines = [];
    console.debug = (...args: unknown[]) => {
      debugLines.push(args.map(String).join(" "));
    };
    console.log = (...args: unknown[]) => {
      logLines.push(args.map(String).join(" "));
    };
    console.error = (...args: unknown[]) => {
      errorLines.push(args.map(String).join(" "));
    };
    console.warn = (...args: unknown[]) => {
      warnLines.push(args.map(String).join(" "));
    };
  });

  afterEach(() => {
    console.debug = originalDebug;
    console.log = originalLog;
    console.error = originalError;
    console.warn = originalWarn;
  });

  test("NO level reaches the console: warn and error are file-only alongside info and debug", () => {
    // The console is the OpenCode TUI's screen, and this pins the whole channel shut.
    // Two rounds of the same defect: info-level "serving" lines in the TUI (2026-09-05),
    // then warn/error JSON printed over a live render during a transient vault timeout
    // (2026-09-11). The first fix exempted faults on the reasoning that only faults belong
    // on a console -- but a fault is when the plugin is LOUDEST, so the carve-out kept the
    // defect for the noisiest case. There is no level-based exemption now; assert all four.
    const real = createLogger();
    real.debug({ provider: "deepseek", state: "available" });
    real.info({ provider: "deepseek", state: "serving" });
    real.warn({ provider: "deepseek", state: "transient", errorCode: "timeout" });
    real.error({ provider: "deepseek", state: "gone", errorClass: "ClaustrumCredentialError" });

    expect(debugLines).toHaveLength(0);
    expect(logLines).toHaveLength(0);
    expect(errorLines).toHaveLength(0);
    expect(warnLines).toHaveLength(0);
  });

  test("serializedLogSink still writes every level to its caller-provided stream and never strips", () => {
    // Regression guard: the default-sink change must not silently move redacted records
    // off the stream a test asserted on. The serialized path keeps everything on the
    // write callback's channel so the existing contract survives.
    const captured: Array<{ level: string; provider?: string; errorCode?: string }> = [];
    const logger = createLogger(serializedLogSink((line) => {
      captured.push(JSON.parse(line));
    }));
    logger.debug({ provider: "deepseek" });
    logger.warn({ provider: "deepseek", errorCode: "timeout" });

    expect(captured).toEqual([
      { level: "debug", provider: "deepseek" },
      { level: "warn", provider: "deepseek", errorCode: "timeout" },
    ]);
  });

  test("file sink writes metadata and creates private parent and file", () => {
    const root = join(tmpdir(), `claustrum-log-${crypto.randomUUID()}`);
    const path = join(root, "nested", "custody.jsonl");
    const logger = createLogger(createFileLogSink({ path }));

    logger.info({ provider: "openai", state: "serving" });

    const line = JSON.parse(readFileSync(path, "utf8"));
    expect(line).toMatchObject({ level: "info", provider: "openai", state: "serving" });
    expect(typeof line.ts).toBe("string");
    expect(line.pid).toBe(process.pid);
    expect(statSync(root).mode & 0o777).toBe(0o700);
    expect(statSync(join(root, "nested")).mode & 0o777).toBe(0o700);
    expect(statSync(path).mode & 0o777).toBe(0o600);
  });

  test("file sink honors override and off disable", () => {
    const root = join(tmpdir(), `claustrum-log-${crypto.randomUUID()}`);
    const override = join(root, "override.jsonl");

    createLogger(createFileLogSink({ env: { CLAUSTRUM_CUSTODY_LOG: override } })).info({ provider: "x" });
    const disabled = join(root, ".local", "state", "cortexkit", "opencode-plugin", "custody.jsonl");
    createLogger(createFileLogSink({ env: { CLAUSTRUM_CUSTODY_LOG: "off", XDG_STATE_HOME: join(root, ".local", "state") } })).info({ provider: "x" });

    expect(existsSync(override)).toBe(true);
    expect(existsSync(disabled)).toBe(false);
  });

  test("file sink writes only FILE_FIELDS", () => {
    const root = join(tmpdir(), `claustrum-log-${crypto.randomUUID()}`);
    const path = join(root, "custody.jsonl");
    createLogger(createFileLogSink({ path })).info({ provider: "openai", state: "serving" });

    const line = JSON.parse(readFileSync(path, "utf8"));
    expect(Object.keys(line).every((key) => (FILE_FIELDS as readonly string[]).includes(key))).toBe(true);
  });

  test("file sink tightens existing directory and rotated file modes", () => {
    const root = join(tmpdir(), `claustrum-log-${crypto.randomUUID()}`);
    const path = join(root, "custody.jsonl");
    mkdirSync(root, { recursive: true, mode: 0o755 });
    writeFileSync(path, "x".repeat(5 * 1024 * 1024 + 1), { mode: 0o644 });
    createLogger(createFileLogSink({ path })).info({ provider: "rotated" });

    expect(statSync(root).mode & 0o777).toBe(0o700);
    expect(statSync(path).mode & 0o777).toBe(0o600);
    expect(statSync(`${path}.1`).mode & 0o777).toBe(0o600);
  });

  test("file sink rotates at five MiB", () => {
    const root = join(tmpdir(), `claustrum-log-${crypto.randomUUID()}`);
    const path = join(root, "custody.jsonl");
    mkdirSync(root, { recursive: true });
    writeFileSync(path, "x".repeat(5 * 1024 * 1024 + 1), { mode: 0o600 });
    createLogger(createFileLogSink({ path })).info({ provider: "rotated" });

    expect(statSync(`${path}.1`).size).toBe(5 * 1024 * 1024 + 1);
    expect(JSON.parse(readFileSync(path, "utf8")).provider).toBe("rotated");
  });

  test("file sink degrades with one console warning when path is unwritable", () => {
    const root = join(tmpdir(), `claustrum-log-${crypto.randomUUID()}`);
    mkdirSync(root, { recursive: true });
    const blocked = join(root, "blocked");
    writeFileSync(blocked, "not a directory");
    const warnings: string[] = [];
    const sink = createFileLogSink({ path: join(blocked, "custody.jsonl"), warn: (message) => warnings.push(message) });

    sink({ level: "info", provider: "x" });
    sink({ level: "info", provider: "y" });

    expect(warnings).toHaveLength(1);
  });

  test("the unavailable notice describes the drop it actually causes, and faults really are gone", () => {
    // Pins the NOTICE against the BEHAVIOUR, not against its own wording. The text used to end
    // "faults still reach the console" -- true while a console sink existed, false the moment that
    // sink was deleted, and nothing failed. Two arms so neither half can drift alone: the claim
    // must not promise a console that carries faults, and warn/error must genuinely produce no
    // console output once the file is unavailable. Re-adding a console fallback reddens arm 2;
    // restoring the old sentence reddens arm 1.
    const root = join(tmpdir(), `claustrum-log-${crypto.randomUUID()}`);
    mkdirSync(root, { recursive: true });
    const blocked = join(root, "blocked");
    writeFileSync(blocked, "not a directory");
    const warnings: string[] = [];
    const logger = createLogger(createFileLogSink({
      path: join(blocked, "custody.jsonl"),
      warn: (message) => warnings.push(message),
    }));

    logger.warn({ provider: "x", state: "transient" });
    logger.error({ provider: "x", errorClass: "ClaustrumCredentialError" });

    expect(warnings).toHaveLength(1);
    expect(warnings[0]).not.toContain("reach the console");
    expect(warnings[0]).toContain("ALL custody telemetry dropped");
    expect(errorLines).toHaveLength(0);
    expect(logLines).toHaveLength(0);
    expect(debugLines).toHaveLength(0);
    expect(warnLines).toHaveLength(0);
  });

  test("file sink excludes free-text error messages", () => {
    const root = join(tmpdir(), `claustrum-log-${crypto.randomUUID()}`);
    const path = join(root, "custody.jsonl");
    const handle = `ckh_${"A".repeat(43)}`;
    const key = "sk-fake-secret-key";
    createLogger(createFileLogSink({ path })).error({ provider: "openai", errorMessage: `${handle} ${key}` });

    const contents = readFileSync(path, "utf8");
    expect(contents).not.toContain(handle);
    expect(contents).not.toContain(key);
  });

  test("file sink rejects secret-bearing values routed into allowlisted shapes", () => {
    const root = join(tmpdir(), `claustrum-log-${crypto.randomUUID()}`);
    const path = join(root, "custody.jsonl");
    const handle = `ckh_${"A".repeat(43)}`;
    const syntaxError = `Unexpected identifier "${handle}"`;
    const key = "sk-fake-secret-key";
    createLogger(createFileLogSink({ path })).error({
      provider: "openai",
      errorClass: syntaxError,
      errorCode: key,
    });

    const contents = readFileSync(path, "utf8");
    expect(contents).not.toContain(handle);
    expect(contents).not.toContain(key);
    expect(contents).toContain('"errorClass":"invalid_shape"');
    expect(contents).toContain('"errorCode":"invalid_shape"');
  });

  test("file sink rejects parser-forbidden provider identifiers", () => {
    const root = join(tmpdir(), `claustrum-log-${crypto.randomUUID()}`);
    const path = join(root, "custody.jsonl");
    const logger = createLogger(createFileLogSink({ path }));
    for (const provider of ["__proto__", "constructor", "openai"]) {
      logger.info({ provider, state: "serving" });
    }

    const records = readFileSync(path, "utf8").trim().split("\n").map((line) => JSON.parse(line));
    expect(records.map((record) => record.provider)).toEqual(["invalid_shape", "invalid_shape", "openai"]);
  });

  test("file sink rejects parser-forbidden account labels", () => {
    const root = join(tmpdir(), `claustrum-log-${crypto.randomUUID()}`);
    const path = join(root, "custody.jsonl");
    const logger = createLogger(createFileLogSink({ path }));
    for (const label of ["__proto__", "prototype", "work-alt"]) {
      logger.info({ provider: "openai", label, state: "serving" });
    }

    const records = readFileSync(path, "utf8").trim().split("\n").map((line) => JSON.parse(line));
    expect(records.map((record) => record.label)).toEqual(["invalid_shape", "invalid_shape", "work-alt"]);
  });

  test("STATES contains every literal state emitted by the producers", () => {
    const sourceFiles = ["plugin.ts", "serve.ts", "freshness.ts"];
    const sources = sourceFiles.map((file) => readFileSync(join(import.meta.dir, "..", file), "utf8"));
    const literals = sources.flatMap((source) => {
      return [...source.matchAll(/state\s*(?::|=)\s*"([^"]+)"/g)].map((match) => match[1]!);
    });
    const errorClasses = sources.flatMap((source) => [...source.matchAll(/errorClass\s*:\s*"([^"]+)"/g)].map((match) => match[1]!));
    const errorCodes = sources.flatMap((source) => [...source.matchAll(/errorCode\s*:\s*"([^"]+)"/g)].map((match) => match[1]!));

    expect(literals.length).toBeGreaterThanOrEqual(3);
    for (const state of literals) expect(STATES.has(state)).toBe(true);
    expect(STATES.has("reauth")).toBe(true);
    expect(errorClasses.length).toBeGreaterThanOrEqual(2);
    for (const errorClass of errorClasses) expect(ERROR_CLASS.test(errorClass)).toBe(true);
    expect(errorCodes.length).toBeGreaterThanOrEqual(2);
    for (const errorCode of errorCodes) expect(ERROR_CODE.test(errorCode)).toBe(true);

    const customErrors = ["errors.ts", "secret-json.ts"].flatMap((file) => {
      const source = readFileSync(join(import.meta.dir, "..", file), "utf8");
      return [...source.matchAll(/export class (\w+Error) extends/g)].map((match) => match[1]!);
    });
    const wireErrorClasses = ["transient", "permanent", "auth_required", "context_overflow"];
    for (const errorClass of [...customErrors, ...wireErrorClasses]) expect(ERROR_CLASS.test(errorClass)).toBe(true);
    expect(isAllHexBody("deadbeef")).toBe(true);
    for (const value of [...errorClasses, ...errorCodes, ...customErrors, ...wireErrorClasses]) {
      expect(isAllHexBody(value)).toBe(false);
    }
  });

  test("producer error classes and codes retain their real shapes", () => {
    const root = join(tmpdir(), `claustrum-log-${crypto.randomUUID()}`);
    const path = join(root, "custody.jsonl");
    const classes = ["SyntaxError", "HandleFileValidationError", "UpstreamFetchError", "FreshnessTickError", "AbortError", "credential_warm", "transient", "permanent", "auth_required", "context_overflow", "other_owner"];
    const codes = ["ENOENT", "EACCES", "ERR_INVALID_ARG_TYPE", "not_found", "needs_reauth", "kind_not_gettable", "sentinel_in_request", "timeout", "transport_error"];
    const logger = createLogger(createFileLogSink({ path }));
    for (const errorClass of classes) logger.error({ provider: "openai", errorClass });
    for (const errorCode of codes) logger.error({ provider: "openai", errorCode });

    const records = readFileSync(path, "utf8").trim().split("\n").map((line) => JSON.parse(line));
    expect(records.slice(0, classes.length).map((record) => record.errorClass)).toEqual(classes);
    expect(records.slice(classes.length).map((record) => record.errorCode)).toEqual(codes);
  });

  test("realistic credential shapes are rejected by both error rules", () => {
    const root = join(tmpdir(), `claustrum-log-${crypto.randomUUID()}`);
    const path = join(root, "custody.jsonl");
    const handle = `ckh_${"A".repeat(43)}`;
    const handlePunctuated = `ckh_${"A".repeat(20)}-${"B".repeat(10)}_${"C".repeat(13)}`;
    const rows = [
      "sk-fake-secret-key",
      `sk-ant-oat01-${"A".repeat(40)}`,
      handle,
      handlePunctuated,
      "a".repeat(64),
      "a".repeat(32),
      "a".repeat(32).replace(/a/g, "z"),
      "a".repeat(16),
      "a".repeat(24),
      "A".repeat(24),
      "1".repeat(24),
    ];
    const logger = createLogger(createFileLogSink({ path }));
    for (const value of rows) logger.error({ provider: "openai", errorClass: value, errorCode: value });

    const records = readFileSync(path, "utf8").trim().split("\n").map((line) => JSON.parse(line));
    for (const record of records) {
      expect(record.errorClass).toBe("invalid_shape");
      expect(record.errorCode).toBe("invalid_shape");
    }
  });

  test("a code-shaped token is indistinguishable from a code and is written as-is (declared residual)", () => {
    const root = join(tmpdir(), `claustrum-log-${crypto.randomUUID()}`);
    const path = join(root, "custody.jsonl");
    const residual = "sk_fake_secret";
    const logger = createLogger(createFileLogSink({ path }));
    logger.error({ provider: "openai", errorCode: residual, errorClass: residual });
    logger.error({ provider: "openai", errorCode: "not_found", errorClass: "not_found" });

    // sk_fake_secret has the same shape as not_found; no provider issues this short token as a
    // secret, and rejecting it would also reject real codes, so this guards against over-tightening.
    const records = readFileSync(path, "utf8").trim().split("\n").map((line) => JSON.parse(line));
    expect(records[0]?.errorCode).toBe(residual);
    expect(records[0]?.errorClass).toBe(residual);
    expect(records[1]?.errorCode).toBe("not_found");
    expect(records[1]?.errorClass).toBe("not_found");
  });

  test("file sink rejects objects routed into allowlisted fields", () => {
    const root = join(tmpdir(), `claustrum-log-${crypto.randomUUID()}`);
    const path = join(root, "custody.jsonl");
    const handle = `ckh_${"A".repeat(43)}`;
    createLogger(createFileLogSink({ path })).error({
      provider: "openai",
      errorCode: { message: `Unexpected identifier "${handle}"` },
      errorClass: new Error(handle),
    } as any);

    const contents = readFileSync(path, "utf8");
    expect(contents).not.toContain(handle);
    expect(contents).not.toContain("message");
    expect(contents).toContain("invalid_shape");
  });
});
