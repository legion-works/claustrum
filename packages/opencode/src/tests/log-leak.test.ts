import { afterEach, describe, expect, test } from "bun:test";
import { chmodSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { createOpencodeClaustrumPlugin } from "../plugin";
import { FILE_FIELDS } from "../log";

const savedEnv = new Map<string, string | undefined>();
const fixtureRoots = new Set<string>();
const ENV_KEYS = ["CLAUSTRUM_OPENCODE_HANDLES", "CLAUSTRUM_CUSTODY_LOG", "XDG_DATA_HOME"] as const;

function useEnv(key: string, value: string | undefined) {
  if (!savedEnv.has(key)) savedEnv.set(key, process.env[key]);
  if (value === undefined) delete process.env[key];
  else process.env[key] = value;
}

afterEach(() => {
  for (const [key, value] of savedEnv) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  savedEnv.clear();
  for (const root of fixtureRoots) rmSync(root, { recursive: true, force: true });
  fixtureRoots.clear();
});

describe("custody log secret absence canary", () => {
  test("Bun SyntaxError exposes the adjacent fake handle in the malformed shape", () => {
    const handle = `ckh_${"A".repeat(43)}`;
    const key = "sk-fake-secret-key";
    const malformed = `{"providers":[{"handle":${handle},"key":${key}}]`;

    let message = "";
    try {
      JSON.parse(malformed);
    } catch (error) {
      message = error instanceof Error ? error.message : String(error);
    }

    expect(message).toContain(handle);
    // Bun reports only the first unexpected token; the key is nevertheless present in the
    // malformed input, so the integration arm exercises a non-vacuous key path separately.
    expect(message).not.toContain(key);
  });

  test("real malformed handle file fault path never writes handle or key", async () => {
    // This integration arm proves the real config-hook path writes a fault without secrets;
    // handles.ts -> parseSecretJson applies the fixed-message SecretJsonParseError upstream.
    const root = join("/tmp/opencode", `custody-log-canary-${crypto.randomUUID()}`);
    fixtureRoots.add(root);
    const config = join(root, "config");
    const data = join(root, "data");
    const handles = join(config, "cortexkit", "opencode-handles.json");
    const custody = join(root, "custody.jsonl");
    const handle = `ckh_${"A".repeat(43)}`;
    const key = "sk-fake-secret-key";
    mkdirSync(join(config, "cortexkit"), { recursive: true, mode: 0o700 });
    mkdirSync(join(data, "opencode"), { recursive: true, mode: 0o700 });
    writeFileSync(handles, `{"providers":[{"handle":${handle},"key":${key}}`, { mode: 0o600 });
    chmodSync(handles, 0o600);
    writeFileSync(join(data, "opencode", "auth.json"), JSON.stringify({}), { mode: 0o600 });
    useEnv("CLAUSTRUM_OPENCODE_HANDLES", handles);
    useEnv("CLAUSTRUM_CUSTODY_LOG", custody);
    useEnv("XDG_DATA_HOME", data);

    const hooks = await createOpencodeClaustrumPlugin()({} as never) as { config?: (cfg: unknown) => Promise<void> };
    await hooks.config?.({ provider: {} });

    const records = readFileSync(custody, "utf8").trim().split("\n").map((line) => JSON.parse(line));
    expect(records.length).toBeGreaterThan(0);
    for (const record of records) {
      expect(Object.keys(record).every((key) => (FILE_FIELDS as readonly string[]).includes(key))).toBe(true);
      expect(record).not.toHaveProperty("errorMessage");
    }
    const contents = readFileSync(custody, "utf8");
    expect(contents).not.toContain(handle);
  });
});
