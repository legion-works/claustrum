import { describe, expect, test } from "bun:test";

import { type ServedCredential } from "@cortexkit/claustrum-client";

import { createOpencodeClaustrumPlugin } from "../index";
import { tombstoneFor } from "../tombstone";

const PROVIDER = "deepseek";
const MAIN_HANDLE = `ckh_${"a".repeat(43)}`;
const BACKUP_HANDLE = `ckh_${"b".repeat(43)}`;

function credential(material: string, recordVersion: number): ServedCredential {
  return { material, recordVersion, expiresAtMs: null };
}

function config() {
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
      fetch: async (request) => {
        requests.push(new Request(request));
        return new Response("upstream", { status: 200 });
      },
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
      fetch: async () => new Response("upstream", { status: ++requests === 1 ? 401 : 200 }),
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

  test("leaves a pre-existing provider option byte-identical when handle validation fails", async () => {
    const cfg = config();
    const before = JSON.stringify(cfg.provider[PROVIDER].options);
    const pluginHooks = await hooks({
      handleReader: async () => { throw new Error("invalid handle file"); },
      authReader: async () => ({ [PROVIDER]: tombstoneFor("api", PROVIDER) }),
      fetch: async () => new Response("must not run"),
      log: () => {},
    });

    await pluginHooks.config?.(cfg);

    expect(JSON.stringify(cfg.provider[PROVIDER].options)).toBe(before);
  });
});
