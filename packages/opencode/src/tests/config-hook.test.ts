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
const AUTH_SCAN_CHUNK_BYTES = 64 * 1024;
const savedEnv = new Map<string, string | undefined>();

type TestConfig = {
  provider: Record<string, { options?: Record<string, unknown>; models?: Record<string, unknown> }>;
};

type RefusalProbe = { apiKey: unknown; forwarded: number };
const refusalProbes = new WeakMap<TestConfig, Map<string, RefusalProbe>>();

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

type AuthSource = { env?: string; disk?: string };

// Mirror provenance: Auth.all/Auth.read in packages/opencode/src/auth/index.ts and the API-key
// loop in provider/provider.ts:1592-1600 at sst/opencode@dc4449df0d. Maintained by delta per
// OpenCode base update alongside opencode-provider-shapes.json.
function opencodeWouldLoad(source: AuthSource): Set<string> {
  const parse = (content: string | undefined): unknown => {
    if (content === undefined) return {};
    try {
      return JSON.parse(content);
    } catch {
      return {};
    }
  };
  const validDiskEntry = (entry: unknown) => {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) return false;
    const candidate = entry as Record<string, unknown>;
    if (candidate.type === "api") return Object.keys(candidate).length === 2 && typeof candidate.key === "string";
    return candidate.type === "oauth" && Object.keys(candidate).length === 4 &&
      typeof candidate.refresh === "string" && typeof candidate.access === "string" && typeof candidate.expires === "number";
  };
  const diskEntries = () => {
    const disk = parse(source.disk);
    if (!disk || typeof disk !== "object" || Array.isArray(disk)) return [];
    return Object.entries(disk).filter(([, entry]) => validDiskEntry(entry));
  };
  let entries: [string, unknown][];
  if (source.env) {
    try {
      const env = JSON.parse(source.env);
      // The host throws at Object.entries(null) before a provider load; no refusal is required.
      entries = env === null ? [] : Object.entries(env);
    } catch {
      entries = diskEntries();
    }
  } else {
    entries = diskEntries();
  }
  return new Set(
    entries.flatMap(([provider, entry]) =>
      (entry as { type?: unknown; key?: unknown; access?: unknown; refresh?: unknown } | null)?.type === "api" &&
        (entry as { key?: unknown }).key === sentinel(provider) ||
      (entry as { type?: unknown; access?: unknown; refresh?: unknown } | null)?.type === "oauth" &&
        ((entry as { access?: unknown }).access === sentinel(provider) || (entry as { refresh?: unknown }).refresh === sentinel(provider))
        ? [provider]
        : [],
    ),
  );
}

function maximumProviderId(prefix: string, index: number) {
  return `${prefix}-${String(index).padStart(5, "0")}-${"x".repeat(48)}`;
}

function tombstoneSource(prefix: string, count: number, deepseekAt?: number) {
  return JSON.stringify(Object.fromEntries(
    Array.from({ length: count }, (_, index) => {
      const provider = index === deepseekAt ? "deepseek" : maximumProviderId(prefix, index);
      return [provider, tombstoneFor("api", provider)];
    }),
  ));
}

async function refusalSet(cfg: TestConfig): Promise<Set<string>> {
  // The property fixture never supplies an owned handle, so the hook can install fetch only to refuse.
  return new Set(Object.entries(cfg.provider)
    .filter(([, provider]) => typeof provider.options?.fetch === "function")
    .map(([provider]) => provider));
}

function prepareRefusalProbe(cfg: TestConfig, provider: string) {
  const options = cfg.provider[provider]?.options;
  if (!options) throw new Error(`missing test provider ${provider}`);
  const probe = { apiKey: options.apiKey, forwarded: 0 };
  options.fetch = async () => {
    probe.forwarded += 1;
    return new Response("must not forward");
  };
  const probes = refusalProbes.get(cfg) ?? new Map<string, RefusalProbe>();
  probes.set(provider, probe);
  refusalProbes.set(cfg, probes);
}

async function expectRefusal(cfg: TestConfig, provider: string, cause: RegExp) {
  const probe = refusalProbes.get(cfg)?.get(provider);
  if (!probe) throw new Error(`missing refusal probe for ${provider}`);
  const options = cfg.provider[provider]?.options;
  expect(options?.apiKey).toBe(probe.apiKey);
  expect(options?.fetch).toBeFunction();
  await expect((options?.fetch as typeof globalThis.fetch)("https://upstream.example")).rejects.toThrow(cause);
  expect(probe.forwarded).toBe(0);
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
    prepareRefusalProbe(cfg, "deepseek");

    await hook(cfg, {
      log: (line) => logs.push(line),
    });

    expect(logs.join("\n")).toContain("CustodySplitError");
    await expectRefusal(cfg, "deepseek", /local credential is real/);
  });

  test("refuses requests for a tombstone without a handle entry", async () => {
    const files = await fixture("orphan");
    await writeHandles(files.handles, { version: 1, providers: [] });
    await writeAuth(files.auth, { deepseek: tombstoneFor("api", "deepseek") });
    const logs: string[] = [];
    const cfg = config("deepseek");
    prepareRefusalProbe(cfg, "deepseek");

    await hook(cfg, { log: (line) => logs.push(line) });

    expect(logs.join("\n")).toContain("CustodyOrphanError");
    await expectRefusal(cfg, "deepseek", /no serving handle/);
  });

  test("logs CustodyOrphanError and leaves an owned handle without an auth.json entry unconfigured", async () => {
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
    prepareRefusalProbe(cfg, "deepseek");

    await hook(cfg, {
      detect: async () => { calls.detect += 1; return { status: "available", schema: 1, wireVersion: 1, endpoints: [] }; },
      clientFactory: async () => { calls.connect += 1; throw new Error("must not connect"); },
    });

    expect(calls).toEqual({ detect: 0, connect: 0 });
    await expectRefusal(cfg, "deepseek", /handle file unavailable/);
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

  test("refuses a non-0600 handle file with a typed ownership cause", async () => {
    const files = await fixture("bad-mode");
    await writeHandles(files.handles, handles("deepseek"));
    await chmod(files.handles, 0o640);
    await writeAuth(files.auth, { deepseek: tombstoneFor("api", "deepseek") });
    const logs: string[] = [];
    const cfg = config("deepseek");
    prepareRefusalProbe(cfg, "deepseek");

    await hook(cfg, { log: (line) => logs.push(line) });

    expect(logs.join("\n")).toContain("HandleFileValidationError");
    await expectRefusal(cfg, "deepseek", /mode must be exactly 0600/);
  });

  test("refuses a handle file owned by another uid through injectable stat metadata", async () => {
    const files = await fixture("bad-owner");
    await writeHandles(files.handles, handles("deepseek"));
    await writeAuth(files.auth, { deepseek: tombstoneFor("api", "deepseek") });
    const logs: string[] = [];
    const cfg = config("deepseek");
    prepareRefusalProbe(cfg, "deepseek");
    const handleReader = (path: string) => readHandleFile(path, {
      currentUid: () => 1000,
      stat: async () => ({ isFile: () => true, mode: 0o100600, uid: 1001 }),
    });

    await hook(cfg, { handleReader, log: (line) => logs.push(line) });

    expect(logs.join("\n")).toContain("HandleFileValidationError");
    await expectRefusal(cfg, "deepseek", /parent must be a directory/);
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
    prepareRefusalProbe(cfg, "deepseek");

    await hook(cfg, { log: (line) => logs.push(line) });

    expect(logs.join("\n")).toContain("HandleFileValidationError");
    await expectRefusal(cfg, "deepseek", /world-writable without sticky bit/);
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

  test("refuses an oversized auth.json with a typed auth-read failure before it can configure custody", async () => {
    const files = await fixture("large-auth-file");
    await writeHandles(files.handles, handles("deepseek"));
    await writeAuth(files.auth, { deepseek: tombstoneFor("api", "deepseek"), padding: "x".repeat(1024 * 1024) });
    const logs: string[] = [];
    const cfg = config("deepseek");
    prepareRefusalProbe(cfg, "deepseek");

    await hook(cfg, { log: (line) => logs.push(line) });

    expect(logs.join("\n")).toContain("AuthFileValidationError");
    expect(logs.join("\n")).toContain("exceeds 1 MiB");
    await expectRefusal(cfg, "deepseek", /auth-read failure.*exceeds 1 MiB/);
  });

  test("refuses an oversized tombstone when the handle file is absent", async () => {
    const files = await fixture("large-auth-missing-handles");
    await writeAuth(files.auth, { deepseek: tombstoneFor("api", "deepseek"), padding: "x".repeat(1024 * 1024) });
    const cfg = config("deepseek");
    prepareRefusalProbe(cfg, "deepseek");

    await hook(cfg);

    await expectRefusal(cfg, "deepseek", /auth-read failure.*1 MiB.*bounded tombstone scan/);
  });

  test("finds a tombstone after 1 MiB when its sentinel crosses a scan chunk boundary", async () => {
    const files = await fixture("large-auth-straddling-sentinel");
    const value = sentinel("deepseek");
    const sentinelOffset = 1024 * 1024 + AUTH_SCAN_CHUNK_BYTES - Math.ceil(value.length / 2);
    const source = `{"padding":"${"x".repeat(sentinelOffset - '{"padding":"'.length)}${value}","deepseek":${JSON.stringify(tombstoneFor("api", "deepseek"))}}`;
    await writeFile(files.auth, source);
    await chmod(files.auth, 0o600);
    const cfg = config("deepseek");
    prepareRefusalProbe(cfg, "deepseek");

    await hook(cfg);

    await expectRefusal(cfg, "deepseek", /bounded tombstone scan/);
  });

  test("leaves a never-migrated oversized auth source without tombstones untouched", async () => {
    const files = await fixture("large-auth-no-tombstone");
    await writeAuth(files.auth, { deepseek: { type: "api", key: "local-key" }, padding: "x".repeat(1024 * 1024) });
    const cfg = config("deepseek");

    await hook(cfg);

    expect(cfg.provider.deepseek.options).toEqual({ baseURL: "https://deepseek.example", headers: { "x-stock": "kept" } });
  });

  test("refuses a malformed auth source containing a tombstone when the handle file is absent", async () => {
    const files = await fixture("malformed-auth-missing-handles");
    await writeFile(files.auth, `{"deepseek":${JSON.stringify(tombstoneFor("api", "deepseek"))}`);
    await chmod(files.auth, 0o600);
    const cfg = config("deepseek");
    prepareRefusalProbe(cfg, "deepseek");

    await hook(cfg);

    await expectRefusal(cfg, "deepseek", /auth-read failure.*invalid JSON.*bounded tombstone scan/);
  });

  test("refuses every scanned tombstone without disturbing configured providers absent from the scan", async () => {
    const files = await fixture("large-auth-two-tombstones");
    await writeAuth(files.auth, {
      deepseek: tombstoneFor("api", "deepseek"),
      xai: tombstoneFor("api", "xai"),
      padding: "x".repeat(1024 * 1024),
    });
    const cfg = config("deepseek", "xai", "anthropic");
    prepareRefusalProbe(cfg, "deepseek");
    prepareRefusalProbe(cfg, "xai");

    await hook(cfg);

    await expectRefusal(cfg, "deepseek", /bounded tombstone scan/);
    await expectRefusal(cfg, "xai", /bounded tombstone scan/);
    expect(cfg.provider.anthropic.options).toEqual({ baseURL: "https://anthropic.example", headers: { "x-stock": "kept" } });
  });

  test("documents the escaped-sentinel scan limitation without refusing a never-migrated source", async () => {
    const files = await fixture("escaped-tombstone-scan-hole");
    // This escaped-sentinel hole and the never-migrated accommodation are the same no-hit branch
    // from two sides; refusing configured providers on no-hit would silently break the latter.
    await writeFile(files.auth, `{"deepseek":{"type":"api","key":"\\u0063laustrum-tombstone:v1:deepseek"},"padding":"${"x".repeat(1024 * 1024)}",`);
    await chmod(files.auth, 0o600);
    const cfg = config("deepseek");

    await hook(cfg);

    expect(cfg.provider.deepseek.options).toEqual({ baseURL: "https://deepseek.example", headers: { "x-stock": "kept" } });
  });

  test("refuses an unparseable auth.json with a typed auth-read failure", async () => {
    const files = await fixture("invalid-auth-file");
    await writeHandles(files.handles, handles("deepseek"));
    await writeFile(files.auth, "{");
    await chmod(files.auth, 0o600);
    const logs: string[] = [];
    const cfg = config("deepseek");
    prepareRefusalProbe(cfg, "deepseek");

    await hook(cfg, { log: (line) => logs.push(line) });

    expect(logs.join("\n")).toContain("AuthFileValidationError");
    expect(logs.join("\n")).toContain("invalid JSON");
    await expectRefusal(cfg, "deepseek", /auth-read failure.*invalid JSON/);
  });

  test("refuses an unreadable auth source for every owned handle provider", async () => {
    const files = await fixture("unreadable-auth-source");
    await writeHandles(files.handles, {
      version: 1,
      providers: [
        handles("deepseek").providers[0],
        handles("xai").providers[0],
      ],
    });
    const logs: string[] = [];
    const cfg = config("deepseek", "xai");
    prepareRefusalProbe(cfg, "deepseek");
    prepareRefusalProbe(cfg, "xai");

    await hook(cfg, {
      authReader: async () => {
        const error = new Error("permission denied");
        Object.assign(error, { code: "EACCES" });
        throw error;
      },
      log: (line) => logs.push(line),
    });

    expect(logs.join("\n")).toContain("auth-read failure");
    await expectRefusal(cfg, "deepseek", /auth-read failure.*permission denied/);
    await expectRefusal(cfg, "xai", /auth-read failure.*permission denied/);
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

  for (const env of [
    { name: "absent", value: undefined, selected: "disk" },
    { name: "empty", value: "", selected: "disk" },
    { name: "malformed", value: "{", selected: "disk" },
    { name: "non-object", value: "[]", selected: "none" },
    { name: "valid", value: JSON.stringify({ deepseek: { type: "api", key: "env-real-key" } }), selected: "env" },
  ] as const) {
    for (const disk of ["tombstone", "real"] as const) {
      test(`matches OpenCode Auth.all for ${env.name} auth content and a ${disk} disk entry`, async () => {
        const files = await fixture(`auth-all-${env.name}-${disk}`);
        await writeHandles(files.handles, handles("deepseek"));
        await writeAuth(files.auth, {
          deepseek: disk === "tombstone"
            ? tombstoneFor("api", "deepseek")
            : { type: "api", key: "disk-real-key" },
        });
        useEnv("OPENCODE_AUTH_CONTENT", env.value);
        const cfg = config("deepseek");
        prepareRefusalProbe(cfg, "deepseek");
        const originalFetch = cfg.provider.deepseek.options?.fetch;

        await hook(cfg);

        const selectedIsTombstone = env.selected === "disk" && disk === "tombstone";
        if (selectedIsTombstone) {
          expect(cfg.provider.deepseek.options?.apiKey).toBe(sentinel("deepseek"));
        } else if (env.selected === "none") {
          expect(cfg.provider.deepseek.options?.apiKey).toBeUndefined();
          expect(cfg.provider.deepseek.options?.fetch).toBe(originalFetch);
        } else {
          await expectRefusal(cfg, "deepseek", /local credential is real/);
        }
      });
    }
  }

  test("refuses a superset of every tombstone provider OpenCode would load on every auth and handle path", async () => {
    const diskTombstone = JSON.stringify({ deepseek: tombstoneFor("api", "deepseek") });
    const oversized = tombstoneSource("oversized", 10_000);
    const manyHits = tombstoneSource("many-hit", 10_000, 257);
    const malformedEntry = JSON.stringify({ deepseek: { type: "api", key: sentinel("deepseek"), extra: true } });
    const sources: Array<{ name: string; source: AuthSource }> = [
      { name: "disk tombstone", source: { disk: diskTombstone } },
      { name: "malformed env", source: { env: "{", disk: diskTombstone } },
      { name: "non-object env", source: { env: "[]", disk: diskTombstone } },
      { name: "null env", source: { env: "null", disk: diskTombstone } },
      { name: "malformed disk entry", source: { disk: malformedEntry } },
      { name: "malformed env entry", source: { env: malformedEntry, disk: diskTombstone } },
      { name: "oversized auth", source: { disk: oversized } },
      { name: "many-hit auth with deepseek after 257 tombstones", source: { disk: manyHits } },
    ];
    const handleStates = ["present", "absent", "unreadable"] as const;
    expect(opencodeWouldLoad({ disk: malformedEntry }).has("deepseek")).toBe(false);
    expect(opencodeWouldLoad({ env: malformedEntry, disk: diskTombstone }).has("deepseek")).toBe(true);

    for (const { name, source } of sources) {
      for (const handleState of handleStates) {
        const files = await fixture(`containment-${name}-${handleState}`);
        if (handleState === "present") await writeHandles(files.handles, { version: 1, providers: [] });
        if (handleState === "unreadable") {
          await writeFile(files.handles, "not json");
          await chmod(files.handles, 0o600);
        }
        if (source.disk !== undefined) {
          await writeFile(files.auth, source.disk);
          await chmod(files.auth, 0o600);
        }
        useEnv("OPENCODE_AUTH_CONTENT", source.env);
        const cfg = { provider: {} } as TestConfig;

        await hook(cfg, { log: () => {} });

        const refusals = await refusalSet(cfg);
        expect([...opencodeWouldLoad(source)].every((provider) => refusals.has(provider))).toBe(true);
      }
    }
  });

  test("streams every malformed many-hit tombstone into the refusal set", async () => {
    const files = await fixture("auth-scan-many-hits");
    const hits = Array.from({ length: 300 }, (_, index) => sentinel(`provider-${index}`)).join(" ");
    await writeFile(files.auth, `{${JSON.stringify(hits)}`);
    await chmod(files.auth, 0o600);
    const cfg = { provider: {} } as TestConfig;

    await hook(cfg, { log: () => {} });

    expect(await refusalSet(cfg)).toEqual(new Set(Array.from({ length: 300 }, (_, index) => `provider-${index}`)));
  });

  test("refuses exactly the three observed providers when a malformed scan stays below the cap", async () => {
    const files = await fixture("auth-scan-three-hits");
    const providers = ["deepseek", "xai", "groq"];
    await writeFile(files.auth, `{${providers.map(sentinel).join(" ")}`);
    await chmod(files.auth, 0o600);
    const cfg = config(...providers, "anthropic");
    for (const provider of providers) prepareRefusalProbe(cfg, provider);

    await hook(cfg);

    for (const provider of providers) await expectRefusal(cfg, provider, /bounded tombstone scan/);
    expect(cfg.provider.anthropic.options).toEqual({ baseURL: "https://anthropic.example", headers: { "x-stock": "kept" } });
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

  test("refuses a request before forwarding when the handle file no longer proves ownership", async () => {
    const files = await fixture("request-handle-ownership");
    await writeHandles(files.handles, handles("deepseek"));
    await writeAuth(files.auth, { deepseek: tombstoneFor("api", "deepseek") });
    const logs: string[] = [];
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
      log: (line) => logs.push(line),
    });
    await chmod(files.handles, 0o640);

    await expect((cfg.provider.deepseek.options?.fetch as typeof globalThis.fetch)("https://upstream.example", {
      headers: { Authorization: `Bearer ${sentinel("deepseek")}` },
    })).rejects.toThrow(/could not verify custody handle ownership.*mode must be exactly 0600/);
    expect(forwarded).toBe(0);
    expect(logs.join("\n")).toContain("mode must be exactly 0600");
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

  test("warns that disabled custody sends tombstones to the wire while avoiding auth and daemon I/O", async () => {
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

    expect(calls).toEqual({ auth: 0, handles: 1, detect: 0 });
    expect(cfg.provider.deepseek.options?.apiKey).toBeUndefined();
    expect(logs).toHaveLength(1);
    expect(logs[0]).toContain("custody_disabled");
    expect(logs[0]).toContain('"level":"warn"');
    expect(logs[0]).toContain("deliberately off");
    expect(logs[0]).toContain("WILL FAIL with a 401");
    expect(logs[0]).toContain("ck auth migrate-opencode --restore <provider>");
    expect(logs[0]).toContain("unsetting the switch");
    expect(logs[0]).toContain("deepseek");
  });

  // OpenCode parses the flag case-sensitively. Serving only on absence or a documented disabling
  // value prevents an unrecognized future value from exposing the sentinel through native auth.
  for (const value of ["1", "true", "yes", "on", "y", "fasle", "TRUE", "maybe", " 1"]) {
    test(`refuses observed tombstones when native LLM mode is enabled with ${JSON.stringify(value)}`, async () => {
      const files = await fixture(`native-llm-${value.replace(/[^a-z0-9]/gi, "_")}-${value === value.toLowerCase() ? "l" : "u"}`);
      await writeHandles(files.handles, handles("deepseek"));
      await writeAuth(files.auth, { deepseek: tombstoneFor("api", "deepseek") });
      useEnv("OPENCODE_EXPERIMENTAL_NATIVE_LLM", value);
      const logs: string[] = [];
      const cfg = config("deepseek");
      prepareRefusalProbe(cfg, "deepseek");

      await hook(cfg, { log: (line) => logs.push(line) });

      expect(logs.join("\n")).toContain("CustodyNativeRuntimeError");
      expect(logs.join("\n")).toContain(`OPENCODE_EXPERIMENTAL_NATIVE_LLM=${value}`);
      await expectRefusal(cfg, "deepseek", new RegExp(`OPENCODE_EXPERIMENTAL_NATIVE_LLM=${value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`));
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
