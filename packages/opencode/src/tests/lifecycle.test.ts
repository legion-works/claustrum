import { describe, expect, test } from "bun:test";

import { type ServedCredential } from "@cortexkit/claustrum-client";

import { createOpencodeClaustrumPlugin } from "../index";
import { tombstoneFor } from "../tombstone";

const PROVIDER = "deepseek";
const MAIN_HANDLE = `ckh_${"a".repeat(43)}`;
const BACKUP_HANDLE = `ckh_${"b".repeat(43)}`;

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

async function hooks(input: Parameters<typeof createOpencodeClaustrumPlugin>[0]) {
  return createOpencodeClaustrumPlugin(input)({} as never) as Promise<{
    config?: (cfg: unknown) => Promise<void>;
  }>;
}

describe("exported OpenCode custody plugin lifecycle", () => {
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

  test("leaves a pre-existing provider option byte-identical when handle validation fails", async () => {
    const cfg = config();
    const before = JSON.stringify(cfg.provider[PROVIDER].options);
    const pluginHooks = await hooks({
      handleReader: async () => { throw new Error("invalid handle file"); },
      authReader: async () => ({ [PROVIDER]: tombstoneFor("api", PROVIDER) }),
      fetch: (async () => new Response("must not run")) as unknown as typeof globalThis.fetch,
      log: () => {},
    });

    await pluginHooks.config?.(cfg);

    expect(JSON.stringify(cfg.provider[PROVIDER].options)).toBe(before);
  });
});
