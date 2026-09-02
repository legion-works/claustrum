import { afterEach, beforeEach, describe, expect, test } from "bun:test";

import { createLogger, serializedLogSink } from "../log";

describe("custody logger", () => {
  const originalLog = console.log;
  const originalError = console.error;
  let logLines: string[];
  let errorLines: string[];

  beforeEach(() => {
    logLines = [];
    errorLines = [];
    console.log = (...args: unknown[]) => {
      logLines.push(args.map(String).join(" "));
    };
    console.error = (...args: unknown[]) => {
      errorLines.push(args.map(String).join(" "));
    };
  });

  afterEach(() => {
    console.log = originalLog;
    console.error = originalError;
  });

  test("the default sink writes debug and info to stdout but warn and error to stderr", () => {
    const logger = createLogger();
    logger.debug({ provider: "deepseek", state: "available" });
    logger.info({ provider: "deepseek", state: "available" });
    logger.warn({ provider: "deepseek", state: "transient", errorCode: "timeout" });
    logger.error({ provider: "deepseek", state: "gone", errorClass: "ClaustrumCredentialError" });

    expect(logLines).toHaveLength(2);
    expect(errorLines).toHaveLength(2);
    expect(logLines[0]).toContain('"level":"debug"');
    expect(logLines[1]).toContain('"level":"info"');
    expect(errorLines[0]).toContain('"level":"warn"');
    expect(errorLines[1]).toContain('"level":"error"');
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
});
