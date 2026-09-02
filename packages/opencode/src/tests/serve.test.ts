import { afterEach, describe, expect, test } from "bun:test";
import { chmod, mkdir, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { ClaustrumCredentialError, type ServedCredential } from "@cortexkit/claustrum-client";

import { CustodyRequestError, CustodySplitError } from "../errors";
import { snapshotRequest } from "../request";
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

  test("keeps sentinel-looking query parameter names untouched while substituting their values", async () => {
    const requests: Request[] = [];
    const fetch = serve({
      upstream: async (request) => {
        requests.push(new Request(request));
        return new Response("ok", { status: 200 });
      },
    });

    await fetch(`https://upstream.example/v1/chat?${encodeURIComponent(SENTINEL)}=${encodeURIComponent(SENTINEL)}`);

    expect(new URL(requests[0]?.url ?? "").search).toBe(`?${encodeURIComponent(SENTINEL)}=material-main`);
  });

  test("allows a sentinel-looking query parameter name with no credential value", async () => {
    const replay = await snapshotRequest(`https://upstream.example/v1/chat?${SENTINEL}`, undefined, SENTINEL);

    expect(replay.withMaterial("material-main").url).toContain(`?${SENTINEL}`);
  });

  test("percent-encodes substituted query material while preserving untouched query bytes", async () => {
    const requests: Request[] = [];
    const material = "a&b=c+d%25#e";
    const fetch = serve({ client: clientWith(credential(material, 7)), upstream: createUpstream([200], requests) });

    await fetch(`https://upstream.example/v1/chat?a=%2F&x=${SENTINEL}&b=1+2`);

    const url = new URL(requests[0]?.url ?? "");
    expect(url.search).toContain("a=%2F");
    expect(url.search).toContain("b=1+2");
    expect([...url.searchParams.keys()]).toHaveLength(3);
    expect(url.searchParams.get("x")).toBe(material);
  });

  test("substitutes a sentinel carried in a lowercase-hex percent-escaped query value", async () => {
    const requests: Request[] = [];
    const fetch = serve({ upstream: createUpstream([200], requests) });
    // Lowercase-hex percent escapes of the sentinel are semantically identical to the
    // canonical uppercase form under decodeURIComponent; the substitution must catch both.
    const lowercaseSentinel = encodeURIComponent(SENTINEL).replace(/%[0-9A-F]{2}/g, (match) =>
      match.toLowerCase(),
    );
    expect(lowercaseSentinel).not.toBe(encodeURIComponent(SENTINEL));

    await fetch(`https://upstream.example/v1/chat?key=${lowercaseSentinel}`);

    const url = new URL(requests[0]?.url ?? "");
    expect(url.searchParams.get("key")).toBe("material-main");
  });

  test("substitutes a sentinel that surrounds other content and uses lowercase-hex escapes", async () => {
    // The previous fix only handled values whose decoded form was exactly the sentinel.
    // A real-world URL can carry `?note=prefix-claustrum-tombstone%3av1%3adeepseek-suffix`
    // where the host escaped `%:` while the receiving parser unflattens both cases to
    // `:` before the upstream sees it. Decoding this value yields `prefix-...-suffix`,
    // NOT the bare sentinel, so the per-param exact-match branch never fires. The
    // fallback needs case-insensitive percent-escape substitution, or a fail-closed
    // refusal on any decoded value that still contains the sentinel.
    const requests: Request[] = [];
    const fetch = serve({ upstream: createUpstream([200], requests) });
    const lowerHexSentinel = encodeURIComponent(SENTINEL).replace(/%[0-9A-F]{2}/g, (match) =>
      match.toLowerCase(),
    );
    const wrapped = `prefix-${lowerHexSentinel}-suffix`;
    expect(decodeURIComponent(wrapped)).toContain(SENTINEL);

    await fetch(`https://upstream.example/v1/chat?note=${wrapped}`);

    const forwarded = requests[0]?.url ?? "";
    // The substitution must eliminate the sentinel in both the encoded and the decoded
    // sense: the literal colon form does NOT appear, and the lower-hex form does not
    // survive either (otherwise the upstream decodes it back to the sentinel).
    expect(forwarded).not.toContain(lowerHexSentinel);
    expect(new URL(forwarded).searchParams.get("note")).toBe(`prefix-material-main-suffix`);
  });

  test("refuses a sentinel embedded in the URL pathname after decode", async () => {
    // The pathname branch previously checked only the raw `pathname` string for the
    // sentinel. An encoded form (`claustrum-tombstone%3Av1%3Adeepseek`) survives because
    // URL.pathname retains percent-escapes; an upstream that unflattens them before
    // matching against its allowlist observes the sentinel as the credential.
    //
    // The refusal is asserted on the typed error class plus the structured `code`
    // (request.ts carries `code: 'sentinel_in_request'`). Asserting on message text
    // would force the serve-path catch to widen what it renders into the operator
    // log; the canary at serve.test.ts:472a below is the contract that catches that
    // regression -- never relax this assertion into a `rejects.toThrow(/sentinel/)`.
    const requests: Request[] = [];
    const fetch = serve({
      upstream: async (request) => {
        requests.push(new Request(request));
        return new Response("must not forward", { status: 200 });
      },
    });
    const caught = await fetch(`https://upstream.example/v1/chat/${encodeURIComponent(SENTINEL)}/respond`)
      .catch((error: unknown) => error);
    expect(caught).toBeInstanceOf(CustodyRequestError);
    expect((caught as CustodyRequestError).code).toBe("sentinel_in_request");
    expect(requests).toHaveLength(0);
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

    expect((await fetch("https://upstream.example/start", {
      method: "POST",
      body: "body",
      headers: { "content-encoding": "gzip", "content-language": "en" },
    })).status).toBe(200);
    expect(requests[1]?.method).toBe("GET");
    expect(requests[1]?.headers.get("content-length")).toBeNull();
    expect(requests[1]?.headers.get("content-encoding")).toBeNull();
    expect(requests[1]?.headers.get("content-language")).toBeNull();
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

  test("preserves HEAD across a same-origin 303 redirect", async () => {
    const requests: Request[] = [];
    const fetch = serve({
      upstream: async (request) => {
        const forwarded = new Request(request);
        requests.push(forwarded);
        return requests.length === 1
          ? new Response(null, { status: 303, headers: { Location: "/final" } })
          : new Response(null, { status: 200 });
      },
    });

    expect((await fetch("https://upstream.example/start", { method: "HEAD" })).status).toBe(200);
    expect(requests.map((request) => request.method)).toEqual(["HEAD", "HEAD"]);
  });

  test("returns a non-redirect 304 response without following its Location", async () => {
    const requests: Request[] = [];
    const fetch = serve({
      upstream: async (request) => {
        requests.push(new Request(request));
        return new Response(null, { status: 304, headers: { Location: "/should-not-follow" } });
      },
    });

    expect((await fetch("https://upstream.example/start")).status).toBe(304);
    expect(requests).toHaveLength(1);
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

      expect((await fetch("https://upstream.example/v1/chat", { headers: { "X-Api-Key": SENTINEL } })).status).toBe(200);
      time += 1_000;
      expect((await fetch("https://upstream.example/v1/chat", { headers: { "X-Api-Key": SENTINEL } })).status).toBe(200);

      expect(client.gets).toEqual([MAIN_HANDLE, BACKUP_HANDLE]);
      expect(requests).toHaveLength(3);
      expect(requests[2]?.headers.get("x-api-key")).toBe("material-backup");
    }
  });

  test("measures an absolute Retry-After against the response-time clock", async () => {
    const requests: Request[] = [];
    const client = clientWith();
    let time = 1_000;
    const fetch = serve({
      client,
      now: () => time,
      upstream: async (request) => {
        requests.push(new Request(request));
        if (requests.length === 1) {
          time = 2_500;
          return new Response("slow down", { status: 429, headers: { "Retry-After": new Date(3_000).toUTCString() } });
        }
        return new Response("ok", { status: 200 });
      },
    });

    await fetch("https://upstream.example/v1/chat", { headers: { "X-Api-Key": SENTINEL } });
    time = 3_100;
    await fetch("https://upstream.example/v1/chat", { headers: { "X-Api-Key": SENTINEL } });

    expect(requests.map((request) => request.headers.get("x-api-key"))).toEqual(["material-main", "material-backup", "material-main"]);
  });

  test("does not log credential-bearing upstream error messages", async () => {
    const entries: unknown[] = [];
    const fetch = createServeFetch({
      provider: PROVIDER,
      accounts: [accounts[0]!],
      client: clientWith(),
      readAuthEntry: () => tombstoneFor("api", PROVIDER),
      upstreamFetch: async () => { throw new Error("MATERIAL-CANARY https://upstream.example/?key=MATERIAL-CANARY"); },
      log: { debug() {}, info() {}, warn() {}, error(entry) { entries.push(entry); } },
    });

    await expect(fetch(`https://upstream.example/?key=${encodeURIComponent(SENTINEL)}`)).rejects.toThrow("upstream request failed");
    expect(JSON.stringify(entries)).not.toContain("MATERIAL-CANARY");
  });

  test("does not expose verifier error messages", async () => {
    const entries: unknown[] = [];
    const fetch = createServeFetch({
      provider: PROVIDER,
      accounts: [accounts[0]!],
      client: clientWith(),
      readAuthEntry: () => tombstoneFor("api", PROVIDER),
      verifyOwnership: async () => { throw new Error("MATERIAL-CANARY https://upstream.example/?key=MATERIAL-CANARY"); },
      upstreamFetch: async () => new Response("must not forward"),
      log: { debug() {}, info() {}, warn() {}, error(entry) { entries.push(entry); } },
    });

    await expect(fetch("https://upstream.example/v1/chat")).rejects.toThrow("could not verify custody handle ownership: Error");
    expect(JSON.stringify(entries)).not.toContain("MATERIAL-CANARY");
  });

  test("does not expose substitution-failure error messages", async () => {
    // The substitution catch (serve.ts ~152) wraps errors thrown by
    // `snapshot.withMaterial`. A future widening of that catch to interpolate
    // `error.message` instead of `error.name` would leak canary material into
    // the operator log. The seam `snapshotRequest` lets this test feed a stub
    // whose `withMaterial` throws a canary-bearing message; assertion covers
    // BOTH the thrown wrapper AND every captured log line.
    const entries: unknown[] = [];
    const canary = `MATERIAL-CANARY ${SENTINEL}`;
    const fetch = createServeFetch({
      provider: PROVIDER,
      accounts: [accounts[0]!],
      client: clientWith(),
      readAuthEntry: () => tombstoneFor("api", PROVIDER),
      upstreamFetch: async () => new Response("must not forward", { status: 200 }),
      log: { debug() {}, info() {}, warn() {}, error(entry) { entries.push(entry); } },
      snapshotRequest: async () => ({
        withMaterial: () => {
          throw new Error(canary);
        },
      }),
    });

    const caught = await fetch("https://upstream.example/v1/chat").catch((error: unknown) => error);
    expect(caught).toBeInstanceOf(CustodyRequestError);
    // Thrown wrapper renders name only -- the canary does not surface in `message`.
    expect((caught as Error).message).not.toContain(canary);
    expect(JSON.stringify(entries)).not.toContain(canary);
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
      // This only catches a broken report budget; it leaves enough scheduler headroom for loaded CI.
      new Promise<Response>((_, reject) => setTimeout(() => reject(new Error("report exceeded 1s budget")), 1_000)),
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
