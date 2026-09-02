import { afterEach, describe, expect, test } from "bun:test";
import { chmod, mkdir, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { ClaustrumCredentialError, type ServedCredential } from "@cortexkit/claustrum-client";

import { CustodySplitError } from "../errors";
import { createServeFetch } from "../serve";
import { sentinel, tombstoneFor } from "../tombstone";

const ROOT = "/tmp/opencode/custody-t7";
const PROVIDER = "deepseek";
const SENTINEL = sentinel(PROVIDER);
const MAIN_HANDLE = `ckh_${"a".repeat(43)}`;
const BACKUP_HANDLE = `ckh_${"b".repeat(43)}`;

type Account = { label: string; handle: string };
type Report = { handle: string; providerStatus: number; recordVersion: number; reporterSource: "direct" };

const accounts: Account[] = [
  { label: "main", handle: MAIN_HANDLE },
  { label: "backup", handle: BACKUP_HANDLE },
];

class FakeClient {
  readonly reports: Report[] = [];
  readonly gets: string[] = [];

  constructor(private readonly credentials: Map<string, ServedCredential | Error>) {}

  async getCredential(handle: string): Promise<ServedCredential> {
    this.gets.push(handle);
    const result = this.credentials.get(handle);
    if (!result) throw new Error(`missing fixture credential for ${handle}`);
    if (result instanceof Error) throw result;
    return result;
  }

  async reportAuthFailure(report: Report): Promise<void> {
    this.reports.push(report);
  }
}

function credential(material: string, recordVersion: number): ServedCredential {
  return { material, recordVersion, expiresAtMs: null };
}

function clientWith(
  main: ServedCredential | Error = credential("material-main", 7),
  backup: ServedCredential | Error = credential("material-backup", 8),
) {
  return new FakeClient(new Map([[MAIN_HANDLE, main], [BACKUP_HANDLE, backup]]));
}

function createUpstream(statuses: Array<number | Response>, requests: Request[]) {
  return async (request: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const forwarded = new Request(request, init);
    requests.push(forwarded);
    for (const [name, value] of forwarded.headers) {
      if (value.includes(SENTINEL)) throw new Error(`sentinel forwarded in ${name}`);
    }
    if (forwarded.url.includes(encodeURIComponent(SENTINEL)) || forwarded.url.includes(SENTINEL)) {
      throw new Error("sentinel forwarded in URL");
    }
    const next = statuses.shift();
    return next instanceof Response ? next : new Response("upstream", { status: next ?? 200 });
  };
}

function serve(input: {
  client?: FakeClient;
  upstream?: (request: RequestInfo | URL, init?: RequestInit) => Promise<Response>;
  now?: () => number;
  readAuthEntry?: () => Promise<unknown> | unknown;
  accounts?: Account[];
}) {
  return createServeFetch({
    provider: PROVIDER,
    accounts: input.accounts ?? accounts,
    client: input.client ?? clientWith(),
    readAuthEntry: input.readAuthEntry ?? (() => tombstoneFor("api", PROVIDER)),
    upstreamFetch: input.upstream ?? (async () => new Response("upstream", { status: 200 })),
    now: input.now,
  });
}

async function fixture(name: string) {
  const root = join(ROOT, name);
  await mkdir(root, { recursive: true });
  const auth = join(root, "auth.json");
  const handles = join(root, "opencode-handles.json");
  await writeFile(handles, JSON.stringify({
    version: 1,
    providers: [{ provider: PROVIDER, shape: "api", serve: "opencode-claustrum", accounts }],
  }));
  await chmod(handles, 0o600);
  return { auth, handles };
}

afterEach(async () => {
  await rm(ROOT, { recursive: true, force: true });
});

describe("OpenCode custody serve fetch", () => {
  test("substitutes every sentinel occurrence in every header value", async () => {
    const requests: Request[] = [];
    const fetch = serve({ upstream: createUpstream([200], requests) });

    await fetch("https://upstream.example/v1/chat", {
      headers: {
        Authorization: `Bearer ${SENTINEL}; ${SENTINEL}`,
        "X-Api-Key": SENTINEL,
      },
    });

    expect(requests).toHaveLength(1);
    expect(requests[0]?.headers.get("authorization")).toBe("Bearer material-main; material-main");
    expect(requests[0]?.headers.get("x-api-key")).toBe("material-main");
  });

  test("substitutes every sentinel occurrence in URL query parameter values", async () => {
    const requests: Request[] = [];
    const fetch = serve({ upstream: createUpstream([200], requests) });

    await fetch(`https://upstream.example/v1/chat?key=${encodeURIComponent(SENTINEL)}&key=before-${encodeURIComponent(SENTINEL)}-after`);

    const url = new URL(requests[0]?.url ?? "");
    expect(url.searchParams.getAll("key")).toEqual(["material-main", "before-material-main-after"]);
  });

  test("reports the credential version used for a 401, clears its cache, and tries the next account", async () => {
    const requests: Request[] = [];
    let currentRecordVersion = 7;
    const client = clientWith({
      material: "material-main",
      get recordVersion() {
        return currentRecordVersion;
      },
      expiresAtMs: null,
    });
    let attempt = 0;
    const fetch = serve({
      client,
      upstream: async (request) => {
        requests.push(new Request(request));
        attempt += 1;
        if (attempt === 1) {
          currentRecordVersion = 9;
          return new Response("unauthorized", { status: 401 });
        }
        return new Response("upstream", { status: 200 });
      },
    });

    expect((await fetch("https://upstream.example/v1/chat")).status).toBe(200);
    expect((await fetch("https://upstream.example/v1/chat")).status).toBe(200);

    expect(client.reports).toEqual([{
      handle: MAIN_HANDLE,
      providerStatus: 401,
      recordVersion: 7,
      reporterSource: "direct",
    }]);
    expect(client.gets).toEqual([MAIN_HANDLE, BACKUP_HANDLE, MAIN_HANDLE]);
    expect(requests).toHaveLength(3);
  });

  test("returns the first successful 3xx response without probing later accounts", async () => {
    const requests: Request[] = [];
    const client = clientWith();
    const fetch = serve({ client, upstream: createUpstream([302, 200], requests) });

    expect((await fetch("https://upstream.example/v1/chat")).status).toBe(302);
    expect(client.gets).toEqual([MAIN_HANDLE]);
    expect(requests).toHaveLength(1);
  });

  test("uses Retry-After seconds, HTTP dates, and a 60-second fallback before failing over", async () => {
    for (const retryAfter of ["2", new Date(1_005_000).toUTCString(), "nonsense"]) {
      const requests: Request[] = [];
      const client = clientWith();
      let time = 1_000_000;
      const fetch = serve({
        client,
        now: () => time,
        upstream: createUpstream([
          new Response("slow down", { status: 429, headers: { "Retry-After": retryAfter } }),
          200,
          200,
        ], requests),
      });

      expect((await fetch("https://upstream.example/v1/chat")).status).toBe(200);
      time += 1_000;
      expect((await fetch("https://upstream.example/v1/chat")).status).toBe(200);

      expect(client.gets).toEqual([MAIN_HANDLE, BACKUP_HANDLE]);
      expect(requests).toHaveLength(3);
    }
  });

  test("puts a 402 account on a one-hour cooldown before trying the next account", async () => {
    const requests: Request[] = [];
    const client = clientWith();
    let time = 1_000_000;
    const fetch = serve({ client, now: () => time, upstream: createUpstream([402, 200, 200], requests) });

    expect((await fetch("https://upstream.example/v1/chat")).status).toBe(200);
    time += 3_599_000;
    expect((await fetch("https://upstream.example/v1/chat")).status).toBe(200);

    expect(client.gets).toEqual([MAIN_HANDLE, BACKUP_HANDLE, BACKUP_HANDLE]);
    expect(requests).toHaveLength(3);
  });

  test("returns 403 immediately without reporting or failover", async () => {
    const requests: Request[] = [];
    const client = clientWith();
    const fetch = serve({ client, upstream: createUpstream([403, 200], requests) });

    expect((await fetch("https://upstream.example/v1/chat")).status).toBe(403);
    expect(client.reports).toEqual([]);
    expect(client.gets).toEqual([MAIN_HANDLE]);
    expect(requests).toHaveLength(1);
  });

  test("returns 5xx immediately without reporting or failover", async () => {
    const requests: Request[] = [];
    const client = clientWith();
    const fetch = serve({ client, upstream: createUpstream([503, 200], requests) });

    expect((await fetch("https://upstream.example/v1/chat")).status).toBe(503);
    expect(client.reports).toEqual([]);
    expect(client.gets).toEqual([MAIN_HANDLE]);
    expect(requests).toHaveLength(1);
  });

  test("re-reads auth.json and throws split custody before forwarding a real local key", async () => {
    const files = await fixture("split-custody");
    await writeFile(files.auth, JSON.stringify({ [PROVIDER]: { type: "api", key: "real-local-key" } }));
    await chmod(files.auth, 0o600);
    let forwarded = 0;
    const fetch = serve({
      readAuthEntry: async () => JSON.parse(await Bun.file(files.auth).text())[PROVIDER],
      upstream: async (request) => {
        forwarded += 1;
        if (new Request(request).url.includes("real-local-key")) throw new Error("real local key forwarded");
        return new Response("must not forward");
      },
    });

    await expect(fetch(`https://upstream.example/v1/chat?key=${encodeURIComponent(SENTINEL)}`)).rejects.toBeInstanceOf(CustodySplitError);
    expect(forwarded).toBe(0);
  });

  test("names only provider and account state summaries when all accounts are exhausted", async () => {
    const requests: Request[] = [];
    const client = clientWith(
      new ClaustrumCredentialError("not_found", "permanent", "gone"),
      credential("material-backup", 8),
    );
    const fetch = serve({
      client,
      upstream: createUpstream([new Response("slow down", { status: 429 }), 200], requests),
    });

    await expect(fetch("https://upstream.example/v1/chat")).rejects.toThrow(/provider=deepseek.*main:gone.*backup:cooldown.*ck auth migrate-opencode/);
    try {
      await fetch("https://upstream.example/v1/chat");
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      expect(message).not.toContain(MAIN_HANDLE);
      expect(message).not.toContain("material-backup");
      expect(message).not.toContain(SENTINEL);
    }
    expect(requests).toHaveLength(1);
  });
});
