import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { createFileLogSink, createLogger, FILE_FIELDS, serializedLogSink, STATES } from "../log";

describe("custody logger", () => {
  const originalDebug = console.debug;
  const originalLog = console.log;
  const originalError = console.error;
  let debugLines: string[];
  let logLines: string[];
  let errorLines: string[];

  beforeEach(() => {
    debugLines = [];
    logLines = [];
    errorLines = [];
    console.debug = (...args: unknown[]) => {
      debugLines.push(args.map(String).join(" "));
    };
    console.log = (...args: unknown[]) => {
      logLines.push(args.map(String).join(" "));
    };
    console.error = (...args: unknown[]) => {
      errorLines.push(args.map(String).join(" "));
    };
  });

  afterEach(() => {
    console.debug = originalDebug;
    console.log = originalLog;
    console.error = originalError;
  });

  test("the console sink carries only faults: info and debug never reach stdout or stderr", () => {
    // The console is the OpenCode TUI's screen. Happy-path telemetry surfacing
    // there is the defect this pins (2026-09-05: three "serving" lines per boot in the TUI).
    const real = createLogger();
    real.debug({ provider: "deepseek", state: "available" });
    real.info({ provider: "deepseek", state: "serving" });
    real.warn({ provider: "deepseek", state: "transient", errorCode: "timeout" });
    real.error({ provider: "deepseek", state: "gone", errorClass: "ClaustrumCredentialError" });

    expect(debugLines).toHaveLength(0);
    expect(logLines).toHaveLength(0);
    expect(errorLines).toHaveLength(2);
    expect(errorLines[0]).toContain('"level":"warn"');
    expect(errorLines[1]).toContain('"level":"error"');
    for (const line of [...debugLines, ...logLines, ...errorLines]) {
      expect(line).not.toContain('"state":"serving"');
    }
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

  test("STATES contains every literal state emitted by the producers", () => {
    const sourceFiles = ["plugin.ts", "serve.ts", "freshness.ts"];
    const literals = sourceFiles.flatMap((file) => {
      const source = readFileSync(join(import.meta.dir, "..", file), "utf8");
      return [...source.matchAll(/state\s*(?::|=)\s*"([^"]+)"/g)].map((match) => match[1]!);
    });

    expect(literals.length).toBeGreaterThanOrEqual(3);
    for (const state of literals) expect(STATES.has(state)).toBe(true);
    expect(STATES.has("reauth")).toBe(true);
  });

  test("producer error classes and codes retain their real shapes", () => {
    const root = join(tmpdir(), `claustrum-log-${crypto.randomUUID()}`);
    const path = join(root, "custody.jsonl");
    const classes = ["SyntaxError", "HandleFileValidationError", "UpstreamFetchError", "FreshnessTickError", "AbortError"];
    const codes = ["ENOENT", "EACCES", "ERR_INVALID_ARG_TYPE", "not_found", "needs_reauth", "kind_not_gettable", "sentinel_in_request"];
    const logger = createLogger(createFileLogSink({ path }));
    for (const errorClass of classes) logger.error({ provider: "openai", errorClass });
    for (const errorCode of codes) logger.error({ provider: "openai", errorCode });

    const records = readFileSync(path, "utf8").trim().split("\n").map((line) => JSON.parse(line));
    expect(records.slice(0, classes.length).map((record) => record.errorClass)).toEqual(classes);
    expect(records.slice(classes.length).map((record) => record.errorCode)).toEqual(codes);
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
