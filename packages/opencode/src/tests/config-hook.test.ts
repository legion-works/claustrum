import { afterEach, describe, expect, test } from "bun:test";
import { chmod, mkdir, rm, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";

import {
  createOpencodeClaustrumPlugin,
  type ConfigHookDependencies,
} from "../plugin";
import { CustodySplitError } from "../errors";
import { handleFileRevision, parseHandleFile, readHandleFile } from "../handles";
import { sentinel, tombstoneFor } from "../tombstone";

const ROOT = "/tmp/opencode/custody-t6";
const HANDLE = `ckh_${"a".repeat(43)}`;
const savedEnv = new Map<string, string | undefined>();

type TestConfig = {
  provider: Record<string, { options?: Record<string, unknown>; models?: Record<string, unknown> }>;
};

function useEnv(key: string, value: string | undefined) {
  if (!savedEnv.has(key)) savedEnv.set(key, process.env[key]);
  if (value === undefined) delete process.env[key];
  else process.env[key] = value;
}

afterEach(async () => {
  for (const [key, value] of savedEnv) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  savedEnv.clear();
  await rm(ROOT, { recursive: true, force: true });
  delete (Object.prototype as { options?: unknown }).options;
});

async function fixture(name: string) {
  const root = join(ROOT, name);
  const config = join(root, "config");
  const data = join(root, "data");
  await mkdir(join(config, "cortexkit"), { recursive: true });
  await mkdir(join(data, "opencode"), { recursive: true });
  useEnv("XDG_CONFIG_HOME", config);
  useEnv("XDG_DATA_HOME", data);
  useEnv("HOME", root);
  return {
    handles: join(config, "cortexkit", "opencode-handles.json"),
    auth: join(data, "opencode", "auth.json"),
  };
}

function handles(provider: string, serve = "opencode-claustrum") {
  return {
    version: 1,
    providers: [{ provider, shape: "api", serve, accounts: [{ label: "main", handle: HANDLE, credential_id: `apikey:${provider}:main` }] }],
  };
}

async function writeHandles(path: string, value: unknown) {
  await writeFile(path, JSON.stringify(value));
  await chmod(path, 0o600);
}

async function writeAuth(path: string, value: unknown) {
  await writeFile(path, JSON.stringify(value));
  await chmod(path, 0o600);
}

function config(...providers: string[]): TestConfig {
  return {
    provider: Object.fromEntries(providers.map((id) => [id, {
      options: { baseURL: `https://${id}.example`, headers: { "x-stock": "kept" } },
      models: { stock: { id: "stock" } },
    }])),
  };
}

async function hook(cfg: TestConfig, deps: ConfigHookDependencies = {}) {
  const hooks = await createOpencodeClaustrumPlugin(deps)({} as never);
  await hooks.config?.(cfg as never);
}

  describe("OpenCode custody config hook (seven ownership cells)", () => {
  test("leaves a real local credential without a handle entry untouched", async () => {
    const files = await fixture("real-unowned");
    await writeHandles(files.handles, { version: 1, providers: [] });
    await writeAuth(files.auth, { deepseek: { type: "api", key: "local-key" } });
    const cfg = config("deepseek");

    await hook(cfg);

    expect(cfg.provider.deepseek.options).toEqual({ baseURL: "https://deepseek.example", headers: { "x-stock": "kept" } });
  });

  test("rejects prototype-bearing provider ids before they reach config materialization", () => {
    expect(() => parseHandleFile(handles("__proto__"))).toThrow("invalid provider");
  });

  test("does not pollute Object.prototype when a hostile handle file names __proto__", async () => {
    const files = await fixture("hostile-provider");
    const hostileHandles = handles("__proto__");
    expect(() => parseHandleFile(hostileHandles)).toThrow("invalid provider");
    await writeHandles(files.handles, hostileHandles);
    await writeFile(files.auth, JSON.stringify({ ["__proto__"]: tombstoneFor("api", "__proto__") }));
    await chmod(files.auth, 0o600);
    const cfg = { provider: {} } as TestConfig;

    await hook(cfg);

    expect("options" in {}).toBe(false);
  });

  test("logs CustodySplitError and refuses requests for a real local credential owned by us", async () => {
    const files = await fixture("split");
    await writeHandles(files.handles, handles("deepseek"));
    await writeAuth(files.auth, { deepseek: { type: "api", key: "local-key" } });
    const logs: string[] = [];
    const cfg = config("deepseek");
    cfg.provider.deepseek.options!.apiKey = "local-key";
    let forwarded = 0;

    await hook(cfg, {
      log: (line) => logs.push(line),
      fetch: (async () => {
        forwarded += 1;
        return new Response("must not forward");
      }) as never,
    });

    expect(logs.join("\n")).toContain("CustodySplitError");
    expect(cfg.provider.deepseek.options?.apiKey).toBe("local-key");
    expect(typeof cfg.provider.deepseek.options?.fetch).toBe("function");
    await expect((cfg.provider.deepseek.options?.fetch as typeof globalThis.fetch)("https://upstream.example")).rejects.toBeInstanceOf(CustodySplitError);
    expect(forwarded).toBe(0);
  });

  test("logs CustodyOrphanError and injects nothing for a tombstone without a handle entry", async () => {
    const files = await fixture("orphan");
    await writeHandles(files.handles, { version: 1, providers: [] });
    await writeAuth(files.auth, { deepseek: tombstoneFor("api", "deepseek") });
    const logs: string[] = [];
    const cfg = config("deepseek");

    await hook(cfg, { log: (line) => logs.push(line) });

    expect(logs.join("\n")).toContain("CustodyOrphanError");
    expect(cfg.provider.deepseek.options?.apiKey).toBeUndefined();
  });

  test("logs CustodyOrphanError and injects nothing when an owned handle has no auth.json entry", async () => {
    const files = await fixture("missing-auth-owned-handle");
    await writeHandles(files.handles, handles("deepseek"));
    await writeAuth(files.auth, {});
    const logs: string[] = [];
    const cfg = config("deepseek");

    await hook(cfg, { log: (line) => logs.push(line) });

    expect(logs.join("\n")).toContain("CustodyOrphanError");
    expect(cfg.provider.deepseek.options?.apiKey).toBeUndefined();
    expect(cfg.provider.deepseek.options?.fetch).toBeUndefined();
  });

  test("merges sentinel and fetch into a tombstoned provider owned by us", async () => {
    const files = await fixture("owned");
    await writeHandles(files.handles, handles("deepseek"));
    await writeAuth(files.auth, { deepseek: tombstoneFor("api", "deepseek") });
    const cfg = config("deepseek");

    await hook(cfg);

    expect(cfg.provider.deepseek.options).toMatchObject({
      apiKey: sentinel("deepseek"),
      baseURL: "https://deepseek.example",
      headers: { "x-stock": "kept" },
    });
    expect(typeof cfg.provider.deepseek.options?.fetch).toBe("function");
    expect(cfg.provider.deepseek.models).toEqual({ stock: { id: "stock" } });
  });

  test("does not detect or connect when no handle file exists", async () => {
    const files = await fixture("missing-handles");
    await writeAuth(files.auth, { deepseek: tombstoneFor("api", "deepseek") });
    const calls = { detect: 0, connect: 0 };
    const cfg = config("deepseek");

    await hook(cfg, {
      detect: async () => { calls.detect += 1; return { status: "available", schema: 1, wireVersion: 1, endpoints: [] }; },
      clientFactory: async () => { calls.connect += 1; throw new Error("must not connect"); },
    });

    expect(calls).toEqual({ detect: 0, connect: 0 });
    expect(cfg.provider.deepseek.options?.apiKey).toBeUndefined();
  });

  test("uses CLAUSTRUM_OPENCODE_HANDLES before the XDG default path", async () => {
    const files = await fixture("path-precedence");
    const explicit = join(ROOT, "path-precedence", "explicit.json");
    useEnv("CLAUSTRUM_OPENCODE_HANDLES", explicit);
    await writeHandles(explicit, handles("deepseek"));
    await writeHandles(files.handles, handles("xai"));
    await writeAuth(files.auth, { deepseek: tombstoneFor("api", "deepseek"), xai: tombstoneFor("api", "xai") });
    const cfg = config("deepseek", "xai");

    await hook(cfg);

    expect(cfg.provider.deepseek.options?.apiKey).toBe(sentinel("deepseek"));
    expect(cfg.provider.xai.options?.apiKey).toBeUndefined();
  });

  test("refuses a non-0600 handle file and injects nothing", async () => {
    const files = await fixture("bad-mode");
    await writeHandles(files.handles, handles("deepseek"));
    await chmod(files.handles, 0o640);
    await writeAuth(files.auth, { deepseek: tombstoneFor("api", "deepseek") });
    const logs: string[] = [];
    const cfg = config("deepseek");

    await hook(cfg, { log: (line) => logs.push(line) });

    expect(logs.join("\n")).toContain("HandleFileValidationError");
    expect(cfg.provider.deepseek.options?.apiKey).toBeUndefined();
  });

  test("refuses a handle file owned by another uid through injectable stat metadata", async () => {
    const files = await fixture("bad-owner");
    await writeHandles(files.handles, handles("deepseek"));
    await writeAuth(files.auth, { deepseek: tombstoneFor("api", "deepseek") });
    const logs: string[] = [];
    const cfg = config("deepseek");
    const handleReader = (path: string) => readHandleFile(path, {
      currentUid: () => 1000,
      stat: async () => ({ isFile: () => true, mode: 0o100600, uid: 1001 }),
    });

    await hook(cfg, { handleReader, log: (line) => logs.push(line) });

    expect(logs.join("\n")).toContain("HandleFileValidationError");
    expect(cfg.provider.deepseek.options?.apiKey).toBeUndefined();
  });

  test("rejects an oversized handle file and never exposes raw handles in its revision", async () => {
    const files = await fixture("large-handle-file");
    await writeHandles(files.handles, { ...handles("deepseek"), padding: "x".repeat(256 * 1024) });

    await expect(readHandleFile(files.handles)).rejects.toThrow("256 KiB");

    await writeHandles(files.handles, handles("deepseek"));
    expect(await handleFileRevision(files.handles)).not.toContain("ckh_");
  });

  test("rejects a symlinked handle file", async () => {
    const files = await fixture("symlink-handle-file");
    const target = join(ROOT, "symlink-handle-file", "target.json");
    await writeHandles(target, handles("deepseek"));
    await symlink(target, files.handles);

    await expect(readHandleFile(files.handles)).rejects.toThrow("symlink");
  });

  test("refuses an oversized auth.json before it can configure a custody fetch", async () => {
    const files = await fixture("large-auth-file");
    await writeHandles(files.handles, handles("deepseek"));
    await writeAuth(files.auth, { deepseek: tombstoneFor("api", "deepseek"), padding: "x".repeat(1024 * 1024) });
    const logs: string[] = [];
    const cfg = config("deepseek");

    await hook(cfg, { log: (line) => logs.push(line) });

    expect(logs.join("\n")).toContain("AuthFileValidationError");
    expect(cfg.provider.deepseek.options?.apiKey).toBeUndefined();
  });

  test("preserves provider and account order when injecting each owned tombstone", async () => {
    const files = await fixture("ordering");
    await writeHandles(files.handles, {
      version: 1,
      providers: [
        { provider: "xai", shape: "api", serve: "opencode-claustrum", accounts: [{ label: "second", handle: HANDLE, credential_id: "apikey:xai:second" }] },
        { provider: "deepseek", shape: "api", serve: "opencode-claustrum", accounts: [{ label: "first", handle: HANDLE, credential_id: "apikey:deepseek:first" }, { label: "backup", handle: `ckh_${"b".repeat(43)}`, credential_id: "apikey:deepseek:backup" }] },
      ],
    });
    await writeAuth(files.auth, { xai: tombstoneFor("api", "xai"), deepseek: tombstoneFor("api", "deepseek") });
    const cfg = config("xai", "deepseek");

    await hook(cfg);

    expect(Object.keys(cfg.provider)).toEqual(["xai", "deepseek"]);
    expect(cfg.provider.xai.options?.apiKey).toBe(sentinel("xai"));
    expect(cfg.provider.deepseek.options?.apiKey).toBe(sentinel("deepseek"));
  });

  test("leaves a tombstone owned by another plugin for that owner", async () => {
    const files = await fixture("other-owner");
    await writeHandles(files.handles, handles("anthropic", "anthropic-auth"));
    await writeAuth(files.auth, { anthropic: tombstoneFor("api", "anthropic") });
    const logs: string[] = [];
    const cfg = config("anthropic");

    await hook(cfg, { log: (line) => logs.push(line) });

    expect(logs.join("\n")).toContain("debug");
    expect(logs.join("\n")).toContain("anthropic-auth");
    expect(cfg.provider.anthropic.options?.apiKey).toBeUndefined();
  });
});
