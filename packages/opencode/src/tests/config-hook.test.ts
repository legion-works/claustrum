import { afterEach, describe, expect, test } from "bun:test";
import { chmod, mkdir, rm, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";

import {
  createOpencodeClaustrumPlugin,
  type ConfigHookDependencies,
} from "../plugin";
import { CustodySplitError, HandleFileValidationError } from "../errors";
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

  test("refuses requests for a tombstone without a handle entry", async () => {
    const files = await fixture("orphan");
    await writeHandles(files.handles, { version: 1, providers: [] });
    await writeAuth(files.auth, { deepseek: tombstoneFor("api", "deepseek") });
    const logs: string[] = [];
    const cfg = config("deepseek");

    await hook(cfg, { log: (line) => logs.push(line) });

    expect(logs.join("\n")).toContain("CustodyOrphanError");
    expect(typeof cfg.provider.deepseek.options?.fetch).toBe("function");
    await expect((cfg.provider.deepseek.options?.fetch as typeof globalThis.fetch)("https://upstream.example"))
      .rejects.toThrow("migrate-opencode");
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

  test("refuses a tombstone when the handle file cannot be read without detecting or connecting", async () => {
    const files = await fixture("missing-handles");
    await writeFile(files.handles, "not json");
    await chmod(files.handles, 0o600);
    await writeAuth(files.auth, { deepseek: tombstoneFor("api", "deepseek") });
    const calls = { detect: 0, connect: 0 };
    const cfg = config("deepseek");

    await hook(cfg, {
      detect: async () => { calls.detect += 1; return { status: "available", schema: 1, wireVersion: 1, endpoints: [] }; },
      clientFactory: async () => { calls.connect += 1; throw new Error("must not connect"); },
    });

    expect(calls).toEqual({ detect: 0, connect: 0 });
    expect(typeof cfg.provider.deepseek.options?.fetch).toBe("function");
    await expect((cfg.provider.deepseek.options?.fetch as typeof globalThis.fetch)("https://upstream.example"))
      .rejects.toThrow("migrate-opencode");
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

  test("rejects a world-writable non-sticky handle parent but accepts a uid-owned 0755 parent", async () => {
    const files = await fixture("handle-parent-mode");
    await writeHandles(files.handles, handles("deepseek"));
    const parent = join(ROOT, "handle-parent-mode", "config", "cortexkit");

    await chmod(parent, 0o777);
    await expect(readHandleFile(files.handles)).rejects.toBeInstanceOf(HandleFileValidationError);

    await chmod(parent, 0o755);
    await expect(readHandleFile(files.handles)).resolves.toMatchObject(handles("deepseek"));
  });

  test("the config hook rejects a world-writable non-sticky handle parent", async () => {
    const files = await fixture("plugin-handle-parent-mode");
    await writeHandles(files.handles, handles("deepseek"));
    await writeAuth(files.auth, { deepseek: tombstoneFor("api", "deepseek") });
    await chmod(join(ROOT, "plugin-handle-parent-mode", "config", "cortexkit"), 0o777);
    const logs: string[] = [];
    const cfg = config("deepseek");

    await hook(cfg, { log: (line) => logs.push(line) });

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

  test("uses OPENCODE_AUTH_CONTENT before a differing auth file during config", async () => {
    const files = await fixture("env-config-auth");
    await writeHandles(files.handles, handles("deepseek"));
    await writeAuth(files.auth, { deepseek: tombstoneFor("api", "deepseek") });
    useEnv("OPENCODE_AUTH_CONTENT", JSON.stringify({ deepseek: { type: "api", key: "real-env-key" } }));
    const cfg = config("deepseek");

    await hook(cfg);

    expect(cfg.provider.deepseek.options?.apiKey).toBeUndefined();
    expect(cfg.provider.deepseek.options?.fetch).toBeFunction();
    await expect((cfg.provider.deepseek.options?.fetch as typeof globalThis.fetch)("https://upstream.example"))
      .rejects.toBeInstanceOf(CustodySplitError);
  });

  test("re-reads OPENCODE_AUTH_CONTENT before the auth file for each served request", async () => {
    const files = await fixture("env-request-auth");
    await writeHandles(files.handles, handles("deepseek"));
    await writeAuth(files.auth, { deepseek: tombstoneFor("api", "deepseek") });
    useEnv("OPENCODE_AUTH_CONTENT", JSON.stringify({ deepseek: tombstoneFor("api", "deepseek") }));
    const cfg = config("deepseek");
    let forwarded = 0;

    await hook(cfg, {
      detect: async () => ({ status: "available", schema: 1, wireVersion: 1, endpoints: [] }),
      clientFactory: async () => ({
        getCredential: async () => ({ material: "vault-material", recordVersion: 1, expiresAtMs: null }),
        reportAuthFailure: async () => {},
      }) as never,
      fetch: (async () => {
        forwarded += 1;
        return new Response("must not forward");
      }) as never,
    });
    useEnv("OPENCODE_AUTH_CONTENT", JSON.stringify({ deepseek: { type: "api", key: "real-env-key" } }));

    await expect((cfg.provider.deepseek.options?.fetch as typeof globalThis.fetch)("https://upstream.example", {
      headers: { Authorization: `Bearer ${sentinel("deepseek")}` },
    })).rejects.toBeInstanceOf(CustodySplitError);
    expect(forwarded).toBe(0);
  });

  test("reconnects after a transient connection failure and its backoff", async () => {
    let now = 0;
    let available = false;
    let detects = 0;
    const cfg = config("deepseek");
    const hooks = await createOpencodeClaustrumPlugin({
      handleReader: async () => handles("deepseek") as never,
      authReader: async () => ({ deepseek: tombstoneFor("api", "deepseek") }),
      detect: async () => {
        detects += 1;
        return available
          ? { status: "available", schema: 1, wireVersion: 1, endpoints: [] }
          : { status: "absent", path: "/tmp/claustrum.sock" };
      },
      clientFactory: async () => ({
        getCredential: async () => ({ material: "vault-material", recordVersion: 1, expiresAtMs: null }),
        reportAuthFailure: async () => {},
      }) as never,
      fetch: (async () => new Response("ok")) as never,
      now: () => now,
    })({} as never);
    await hooks.config?.(cfg as never);
    const fetch = cfg.provider.deepseek.options?.fetch as typeof globalThis.fetch;

    await expect(fetch("https://upstream.example", { headers: { Authorization: `Bearer ${sentinel("deepseek")}` } }))
      .rejects.toThrow("accounts exhausted");
    now += 60_000;
    available = true;

    expect((await fetch("https://upstream.example", { headers: { Authorization: `Bearer ${sentinel("deepseek")}` } })).status).toBe(200);
    expect(detects).toBe(2);
  });

  test("returns an inert plugin before touching custody files when CLAUSTRUM_CUSTODY_DISABLE is set", async () => {
    useEnv("CLAUSTRUM_CUSTODY_DISABLE", "1");
    const calls = { auth: 0, handles: 0, detect: 0 };
    const logs: string[] = [];
    const cfg = config("deepseek");

    const hooks = await createOpencodeClaustrumPlugin({
      authReader: async () => { calls.auth += 1; return { deepseek: tombstoneFor("api", "deepseek") }; },
      handleReader: async () => { calls.handles += 1; return handles("deepseek") as never; },
      detect: async () => { calls.detect += 1; return { status: "available", schema: 1, wireVersion: 1, endpoints: [] }; },
      log: (line) => logs.push(line),
    })({} as never);
    await hooks.config?.(cfg as never);

    expect(calls).toEqual({ auth: 0, handles: 0, detect: 0 });
    expect(cfg.provider.deepseek.options?.apiKey).toBeUndefined();
    expect(logs).toHaveLength(1);
    expect(logs[0]).toContain("custody_disabled");
  });

  // OpenCode reads the flag through Effect's Config.boolean (effect dist/Config.js:541-562):
  // enabling spellings `true yes on 1 y`, disabling `false no off 0 n`, CASE-SENSITIVE. The guard
  // fails closed: only the five disabling spellings (or absence) let custody serve. `TRUE` and
  // `maybe` do not enable OpenCode's native runtime, but they are refused anyway rather than
  // guessed at — an under-firing guard here sends the sentinel to the wire as the key.
  for (const value of ["1", "true", "yes", "on", "y", "TRUE", "maybe", " 1"]) {
    test(`refuses observed tombstones when native LLM mode is enabled with ${JSON.stringify(value)}`, async () => {
      const files = await fixture(`native-llm-${value.replace(/[^a-z0-9]/gi, "_")}-${value === value.toLowerCase() ? "l" : "u"}`);
      await writeHandles(files.handles, handles("deepseek"));
      await writeAuth(files.auth, { deepseek: tombstoneFor("api", "deepseek") });
      useEnv("OPENCODE_EXPERIMENTAL_NATIVE_LLM", value);
      const logs: string[] = [];
      const cfg = config("deepseek");

      await hook(cfg, { log: (line) => logs.push(line) });

      expect(logs.join("\n")).toContain("CustodyNativeRuntimeError");
      await expect((cfg.provider.deepseek.options?.fetch as typeof globalThis.fetch)("https://upstream.example"))
        .rejects.toThrow("native LLM");
    });
  }

  for (const value of ["0", "false", "off", "no", "n"]) {
    test(`serves normally when native LLM mode is off with ${JSON.stringify(value)}`, async () => {
      const files = await fixture(`native-llm-off-${value}`);
      await writeHandles(files.handles, handles("deepseek"));
      await writeAuth(files.auth, { deepseek: tombstoneFor("api", "deepseek") });
      useEnv("OPENCODE_EXPERIMENTAL_NATIVE_LLM", value);
      const logs: string[] = [];
      const cfg = config("deepseek");

      await hook(cfg, { log: (line) => logs.push(line) });

      expect(logs.join("\n")).not.toContain("CustodyNativeRuntimeError");
      expect(cfg.provider.deepseek.options?.apiKey).toBe(sentinel("deepseek"));
    });
  }
});
