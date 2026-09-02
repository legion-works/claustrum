import { afterEach, describe, expect, test } from "bun:test";

import { type ServedCredential } from "@cortexkit/claustrum-client";

import { createOpencodeClaustrumPlugin } from "../index";
import { tombstoneFor } from "../tombstone";

const PROVIDER = "deepseek";
const MAIN_HANDLE = `ckh_${"a".repeat(43)}`;
const BACKUP_HANDLE = `ckh_${"b".repeat(43)}`;

// The plugin reads OPENCODE_AUTH_CONTENT, OPENCODE_EXPERIMENTAL_NATIVE_LLM, and
// CLAUSTRUM_CUSTODY_DISABLE at runtime. Each overrides the injected authReader/handleReader
// dependencies and would silently reroute the assertion: OPENCODE_AUTH_CONTENT bypasses the
// injected authReader, CLAUSTRUM_CUSTODY_DISABLE=1 swaps in a no-op config hook, and
// OPENCODE_EXPERIMENTAL_NATIVE_LLM refuses the provider. Clear the three vars per-test so
// the lifecycle suite exercises the injected dependencies deterministically — same pattern
// config-hook.test.ts uses.
const savedEnv = new Map<string, string | undefined>();
const ENV_KEYS = ["OPENCODE_AUTH_CONTENT", "OPENCODE_EXPERIMENTAL_NATIVE_LLM", "CLAUSTRUM_CUSTODY_DISABLE"] as const;

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
});

type TestConfig = {
  provider: Record<string, {
    options: {
      baseURL: string;
      headers: { "x-stock": string };
      fetch?: typeof globalThis.fetch;
      apiKey?: string;
    };
  }>;
};

function credential(material: string, recordVersion: number): ServedCredential {
  return { material, recordVersion, expiresAtMs: null };
}

function config(): TestConfig {
  return {
    provider: {
      [PROVIDER]: {
        options: { baseURL: "https://upstream.test", headers: { "x-stock": "kept" } },
      },
    },
  };
}

// Construct the plugin WITHOUT clearing the three env vars, so the test that exercises
// isolation can set them BEFORE calling this. Other tests use `hooks()` which clears.
async function createIsolatedHooks(input: Parameters<typeof createOpencodeClaustrumPlugin>[0]) {
  return createOpencodeClaustrumPlugin(input)({} as never) as Promise<{
    config?: (cfg: unknown) => Promise<void>;
  }>;
}

async function hooks(input: Parameters<typeof createOpencodeClaustrumPlugin>[0]) {
  for (const key of ENV_KEYS) useEnv(key, undefined);
  return createOpencodeClaustrumPlugin(input)({} as never) as Promise<{
    config?: (cfg: unknown) => Promise<void>;
  }>;
}

describe("exported OpenCode custody plugin lifecycle", () => {
  test("short-circuits when CLAUSTRUM_CUSTODY_DISABLE=1", async () => {
    // CLAUSTRUM_CUSTODY_DISABLE=1 short-circuits: the hook reads handles only to
    // enumerate owned providers for the warning; authReader is never called because
    // OPENCODE_AUTH_CONTENT and OPENCODE_EXPERIMENTAL_NATIVE_LLM never reach the
    // injection path. The "no-op" property is "no fetch installed" — which is what
    // proves the disabled branch was taken and the other two vars did NOT steer the
    // outcome.
    useEnv("OPENCODE_AUTH_CONTENT", '{"deepseek":{"type":"api","key":"env-real-key"}}');
    useEnv("OPENCODE_EXPERIMENTAL_NATIVE_LLM", "true");
    useEnv("CLAUSTRUM_CUSTODY_DISABLE", "1");

    let authCalls = 0;
    let handleCalls = 0;
    const hooks = await createIsolatedHooks({
      handleReader: async () => {
        handleCalls += 1;
        return {
          version: 1,
          providers: [{ provider: PROVIDER, shape: "api", serve: "opencode-claustrum", accounts: [{ label: "main", handle: MAIN_HANDLE, credential_id: "id" }] }],
        };
      },
      authReader: async () => { authCalls += 1; return { [PROVIDER]: tombstoneFor("api", PROVIDER) }; },
      detect: async () => ({ status: "available", schema: 1, wireVersion: 1, endpoints: [] }),
      clientFactory: async () => ({
        getCredential: async () => credential("vault-material", 1),
        reportAuthFailure: async () => {},
      }) as never,
      fetch: ((async () => new Response("upstream", { status: 200 })) as unknown) as typeof globalThis.fetch,
      log: () => {},
    });
    const cfg = config();
    await hooks.config?.(cfg);
    expect(authCalls).toBe(0);
    expect(handleCalls).toBe(1);
    expect(cfg.provider[PROVIDER].options.apiKey).toBeUndefined();
    expect(cfg.provider[PROVIDER].options.fetch).toBeUndefined();
  });

  test("refuses tombstones in native LLM mode", async () => {
    // After unsetting CLAUSTRUM_CUSTODY_DISABLE but keeping OPENCODE_EXPERIMENTAL_NATIVE_LLM
    // and OPENCODE_AUTH_CONTENT set to a tombstone-shaped content (so the auth-source
    // override is exercised), the native mode refusal must drive the choice — the
    // injected dependencies are observable because CLAUSTRUM_CUSTODY_DISABLE no longer
    // short-circuits the path. authReader is intentionally rigged to throw — if
    // OPENCODE_AUTH_CONTENT leaks, this is the failure mode.
    useEnv("OPENCODE_AUTH_CONTENT", JSON.stringify({ [PROVIDER]: tombstoneFor("api", PROVIDER) }));
    useEnv("OPENCODE_EXPERIMENTAL_NATIVE_LLM", "true");
    useEnv("CLAUSTRUM_CUSTODY_DISABLE", undefined);

    const hooks = await createIsolatedHooks({
      handleReader: async () => ({
        version: 1,
        providers: [{ provider: PROVIDER, shape: "api", serve: "opencode-claustrum", accounts: [{ label: "main", handle: MAIN_HANDLE, credential_id: "id" }] }],
      }),
      authReader: async () => { throw new Error("must use OPENCODE_AUTH_CONTENT"); },
      detect: async () => ({ status: "available", schema: 1, wireVersion: 1, endpoints: [] }),
      clientFactory: async () => ({
        getCredential: async () => credential("vault-material", 1),
        reportAuthFailure: async () => {},
      }) as never,
      fetch: ((async () => new Response("upstream", { status: 200 })) as unknown) as typeof globalThis.fetch,
      log: () => {},
    });
    const cfg = config();
    await hooks.config?.(cfg);
    expect(cfg.provider[PROVIDER].options.apiKey).toBeUndefined();
    expect(typeof cfg.provider[PROVIDER].options.fetch).toBe("function");
    await expect((cfg.provider[PROVIDER].options.fetch as typeof globalThis.fetch)("https://upstream.test"))
      .rejects.toThrow(/native LLM mode/);
  });
  test("exports the OpenCode v1 plugin object from a dedicated file-plugin entrypoint", async () => {
    const module = await import("../opencode-plugin") as unknown as { default?: { id?: unknown; server?: unknown } };

    expect(module.default?.id).toBe("opencode-claustrum");
    expect(typeof module.default?.server).toBe("function");
  });

  test("injects an owned tombstone provider and substitutes through the real plugin fetch", async () => {
    const cfg = config();
    const requests: Request[] = [];
    const pluginHooks = await hooks({
      handleReader: async () => ({
        version: 1,
        providers: [{ provider: PROVIDER, shape: "api", serve: "opencode-claustrum", accounts: [{ label: "main", handle: MAIN_HANDLE, credential_id: "id" }] }],
      }),
      authReader: async () => ({ [PROVIDER]: tombstoneFor("api", PROVIDER) }),
      detect: async () => ({ status: "available", schema: 1, wireVersion: 1, endpoints: [] }),
      clientFactory: async () => ({
        getCredential: async () => credential("vault-material", 4),
        reportAuthFailure: async () => {},
      }) as never,
      fetch: (async (request) => {
        requests.push(new Request(request));
        return new Response("upstream", { status: 200 });
      }) as typeof globalThis.fetch,
      log: () => {},
    });

    await pluginHooks.config?.(cfg);
    const fetch = cfg.provider[PROVIDER].options.fetch as typeof globalThis.fetch;
    expect((await fetch("https://upstream.test", { headers: { Authorization: `Bearer ${cfg.provider[PROVIDER].options.apiKey}` } })).status).toBe(200);
    expect(requests[0]?.headers.get("authorization")).toBe("Bearer vault-material");
  });

  test("reports a 401 against the served version and fails over through the injected fetch", async () => {
    const cfg = config();
    const reports: unknown[] = [];
    let requests = 0;
    const pluginHooks = await hooks({
      handleReader: async () => ({
        version: 1,
        providers: [{
          provider: PROVIDER,
          shape: "api",
          serve: "opencode-claustrum",
          accounts: [
            { label: "main", handle: MAIN_HANDLE, credential_id: "id" },
            { label: "backup", handle: BACKUP_HANDLE, credential_id: "id2" },
          ],
        }],
      }),
      authReader: async () => ({ [PROVIDER]: tombstoneFor("api", PROVIDER) }),
      detect: async () => ({ status: "available", schema: 1, wireVersion: 1, endpoints: [] }),
      clientFactory: async () => ({
        getCredential: async (handle: string) => handle === MAIN_HANDLE ? credential("first", 7) : credential("second", 8),
        reportAuthFailure: async (report: unknown) => { reports.push(report); },
      }) as never,
      fetch: (async () => new Response("upstream", { status: ++requests === 1 ? 401 : 200 })) as unknown as typeof globalThis.fetch,
      log: () => {},
    });

    await pluginHooks.config?.(cfg);
    const fetch = cfg.provider[PROVIDER].options.fetch as typeof globalThis.fetch;
    expect((await fetch("https://upstream.test", { headers: { Authorization: `Bearer ${cfg.provider[PROVIDER].options.apiKey}` } })).status).toBe(200);
    expect(reports).toEqual([{
      handle: MAIN_HANDLE,
      providerStatus: 401,
      recordVersion: 7,
      reporterSource: "direct",
    }]);
  });

  test("refuses the exported plugin fetch before forwarding a real credential owned by custody", async () => {
    const cfg = config();
    cfg.provider[PROVIDER].options.apiKey = "local-key";
    let forwarded = 0;
    const pluginHooks = await hooks({
      handleReader: async () => ({
        version: 1,
        providers: [{ provider: PROVIDER, shape: "api", serve: "opencode-claustrum", accounts: [{ label: "main", handle: MAIN_HANDLE, credential_id: "id" }] }],
      }),
      authReader: async () => ({ [PROVIDER]: { type: "api", key: "local-key" } }),
      fetch: (async () => {
        forwarded += 1;
        return new Response("must not forward");
      }) as never,
      log: () => {},
    });

    await pluginHooks.config?.(cfg);
    const fetch = cfg.provider[PROVIDER].options.fetch as typeof globalThis.fetch;

    expect(cfg.provider[PROVIDER].options.apiKey).toBe("local-key");
    await expect(fetch("https://upstream.test")).rejects.toThrow("migrate-opencode");
    expect(forwarded).toBe(0);
  });

  test("preserves existing options and injects a refusing fetch when handle validation fails", async () => {
    const cfg = config();
    const pluginHooks = await hooks({
      handleReader: async () => { throw new Error("invalid handle file"); },
      authReader: async () => ({ [PROVIDER]: tombstoneFor("api", PROVIDER) }),
      fetch: (async () => new Response("must not run")) as unknown as typeof globalThis.fetch,
      log: () => {},
    });

    await pluginHooks.config?.(cfg);

    expect(cfg.provider[PROVIDER].options.baseURL).toBe("https://upstream.test");
    expect(cfg.provider[PROVIDER].options.headers).toEqual({ "x-stock": "kept" });
    await expect((cfg.provider[PROVIDER].options.fetch as typeof globalThis.fetch)("https://upstream.test"))
      .rejects.toThrow("migrate-opencode");
  });
});
