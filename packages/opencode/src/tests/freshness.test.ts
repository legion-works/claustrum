import { describe, expect, test } from "bun:test";

import { ClaustrumCredentialError, type ServedCredential } from "@cortexkit/claustrum-client";

import { FreshnessController } from "../freshness";
import { createLogger } from "../log";
import { createOpencodeClaustrumPlugin } from "../plugin";
import { createServeFetch } from "../serve";
import { sentinel, tombstoneFor } from "../tombstone";

const PROVIDER = "deepseek";
const MAIN_HANDLE = `ckh_${"a".repeat(43)}`;
const BACKUP_HANDLE = `ckh_${"b".repeat(43)}`;

type Account = { label: string; handle: string; credential_id: string };
type IntervalCallback = () => void;

const apiAccounts: Account[] = [
  { label: "main", handle: MAIN_HANDLE, credential_id: "apikey:deepseek:main" },
  { label: "backup", handle: BACKUP_HANDLE, credential_id: "apikey:deepseek:backup" },
];

function credential(material: string, recordVersion = 1): ServedCredential {
  return { material, recordVersion, expiresAtMs: null };
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}

class FakeClient {
  readonly gets: Array<{ handle: string; minTtlMs?: number }> = [];
  readonly reports: Array<{ handle: string; recordVersion: number }> = [];

  constructor(private readonly get: (handle: string, minTtlMs?: number) => Promise<ServedCredential>) {}

  async getCredential(handle: string, minTtlMs?: number): Promise<ServedCredential> {
    this.gets.push({ handle, minTtlMs });
    return this.get(handle, minTtlMs);
  }

  async reportAuthFailure(input: { handle: string; recordVersion: number }): Promise<void> {
    this.reports.push(input);
  }
}

function fakeInterval() {
  const callbacks: IntervalCallback[] = [];
  const cleared: unknown[] = [];
  const unrefs: unknown[] = [];
  return {
    callbacks,
    cleared,
    unrefs,
    setInterval(callback: IntervalCallback) {
      const token = { unref: () => unrefs.push(token) };
      callbacks.push(callback);
      return token;
    },
    clearInterval(token: unknown) {
      cleared.push(token);
    },
  };
}

function controller(input: {
  shape?: "api" | "oauth";
  accounts?: Account[];
  client: FakeClient;
  now?: () => number;
  handleVersion?: () => string;
  intervals?: ReturnType<typeof fakeInterval>;
  setTimeout?: (callback: () => void, ms: number) => unknown;
}) {
  return new FreshnessController({
    shape: input.shape ?? "api",
    accounts: input.accounts ?? apiAccounts,
    client: input.client,
    now: input.now,
    handleVersion: input.handleVersion,
    setInterval: input.intervals?.setInterval,
    clearInterval: input.intervals?.clearInterval,
    setTimeout: input.setTimeout,
  });
}

describe("custody freshness", () => {
  test("re-observes an api account only on the next request after ten minutes", async () => {
    let now = 0;
    const client = new FakeClient(async () => credential("material"));
    const freshness = controller({ client, now: () => now });

    await freshness.resolve(apiAccounts[0]!);
    now = 9 * 60_000;
    await freshness.resolve(apiAccounts[0]!);
    now = 10 * 60_000;
    await freshness.resolve(apiAccounts[0]!);

    expect(client.gets).toEqual([
      { handle: MAIN_HANDLE, minTtlMs: undefined },
      { handle: MAIN_HANDLE, minTtlMs: undefined },
    ]);
  });

  test("ticks oauth accounts without traffic using the configured minimum TTL", async () => {
    const intervals = fakeInterval();
    const client = new FakeClient(async () => credential("oauth-material"));
    controller({ shape: "oauth", client, intervals });

    expect(intervals.callbacks).toHaveLength(1);
    expect(intervals.unrefs).toHaveLength(1);
    intervals.callbacks[0]!();
    await Promise.resolve();
    await Promise.resolve();

    expect(client.gets).toEqual([
      { handle: MAIN_HANDLE, minTtlMs: 270 * 60_000 },
      { handle: BACKUP_HANDLE, minTtlMs: 270 * 60_000 },
    ]);
  });

  test("bounds a cold warm to 100ms while the get continues detached", async () => {
    const pending = deferred<ServedCredential>();
    let calls = 0;
    const client = new FakeClient(async () => ++calls === 1 ? pending.promise : credential("fresh"));
    let timeoutCallback: (() => void) | undefined;
    const freshness = controller({
      client,
      setTimeout: (callback, ms) => {
        expect(ms).toBe(100);
        timeoutCallback = callback;
        return {};
      },
    });

    const resolved = freshness.resolve(apiAccounts[0]!);
    await Promise.resolve();
    expect(timeoutCallback).toBeFunction();
    timeoutCallback?.();
    await Promise.resolve();
    await Promise.resolve();
    expect(await resolved).toBeUndefined();
    expect(client.gets).toEqual([{ handle: MAIN_HANDLE, minTtlMs: undefined }]);
    pending.resolve(credential("eventual-material"));
    expect(await freshness.resolve(apiAccounts[0]!)).toEqual(credential("eventual-material"));
    expect(client.gets).toEqual([{ handle: MAIN_HANDLE, minTtlMs: undefined }]);
  });

  test("does not cache a warm that completed after its handle revision changed", async () => {
    let version = "one";
    const pending = deferred<ServedCredential>();
    let calls = 0;
    const client = new FakeClient(async () => ++calls === 1 ? pending.promise : credential("fresh"));
    const freshness = controller({ client, handleVersion: () => version });

    const first = freshness.resolve(apiAccounts[0]!);
    await Promise.resolve();
    version = "two";
    await freshness.resolve(apiAccounts[0]!);
    pending.resolve(credential("stale"));
    await first;
    await Promise.resolve();

    expect(await freshness.resolve(apiAccounts[0]!)).toEqual(credential("fresh"));
    expect(client.gets).toHaveLength(2);
  });

  test("keeps the longer account cooldown when a later response asks for less time", () => {
    let now = 1_000;
    const freshness = controller({ client: new FakeClient(async () => credential("unused")), now: () => now });

    freshness.cooldown(apiAccounts[0]!, 60 * 60_000);
    now += 1;
    freshness.cooldown(apiAccounts[0]!, 1_000);
    now += 2_000;

    expect(freshness.state(apiAccounts[0]!)).toBe("cooldown");
  });

  test("does not mislabel an immediately failed warm as a timeout", async () => {
    const entries: unknown[] = [];
    const freshness = new FreshnessController({
      provider: PROVIDER,
      shape: "api",
      accounts: [apiAccounts[0]!],
      client: new FakeClient(async () => { throw new Error("daemon down"); }),
      log: createLogger((entry) => entries.push(entry)),
      setTimeout: () => ({}),
    });

    await freshness.resolve(apiAccounts[0]!);

    expect(entries.some((entry) => (entry as { errorCode?: string }).errorCode === "timeout")).toBe(false);
  });

  test("warns once when an oauth cache serves after a recent transport failure", async () => {
    const entries: unknown[] = [];
    let fail = false;
    const client = new FakeClient(async () => {
      if (fail) throw new Error("daemon down");
      return credential("cached");
    });
    const freshness = new FreshnessController({
      provider: PROVIDER,
      shape: "oauth",
      accounts: [apiAccounts[0]!],
      client,
      log: createLogger((entry) => entries.push(entry)),
      setInterval: () => ({ unref: () => {} }),
      clearInterval: () => {},
      setTimeout: (callback) => {
        queueMicrotask(callback);
        return {};
      },
    });

    await freshness.tick();
    fail = true;
    await freshness.tick();
    expect(await freshness.resolve(apiAccounts[0]!)).toEqual(credential("cached"));
    expect(await freshness.resolve(apiAccounts[0]!)).toEqual(credential("cached"));

    expect(entries.filter((entry) => (entry as { errorCode?: string }).errorCode === "serving_cached")).toHaveLength(1);
  });

  test("warms each oauth account at most once per tick", async () => {
    const pending = deferred<ServedCredential>();
    const intervals = fakeInterval();
    const client = new FakeClient(async () => pending.promise);
    const freshness = controller({
      shape: "oauth",
      client,
      intervals,
      setTimeout: (callback) => {
        queueMicrotask(callback);
        return {};
      },
    });

    await freshness.tick();
    await freshness.tick();

    expect(client.gets).toEqual([
      { handle: MAIN_HANDLE, minTtlMs: 270 * 60_000 },
      { handle: BACKUP_HANDLE, minTtlMs: 270 * 60_000 },
    ]);
  });

  test("backs off per handle and only clears a gone handle after its source changes", async () => {
    let now = 0;
    let version = "mtime:1/content:one";
    const outcomes: Array<ServedCredential | Error> = [
      new Error("transient"),
      new ClaustrumCredentialError("needs_reauth", "auth_required", "reauth"),
      new ClaustrumCredentialError("not_found", "permanent", "gone"),
      credential("replaced"),
    ];
    const client = new FakeClient(async () => {
      const outcome = outcomes.shift();
      if (outcome instanceof Error) throw outcome;
      return outcome!;
    });
    const freshness = controller({ client, now: () => now, handleVersion: () => version });

    expect(await freshness.resolve(apiAccounts[0]!)).toBeUndefined();
    now = 59_999;
    expect(await freshness.resolve(apiAccounts[0]!)).toBeUndefined();
    now = 60_000;
    expect(await freshness.resolve(apiAccounts[0]!)).toBeUndefined();
    now += 5 * 60_000 - 1;
    expect(await freshness.resolve(apiAccounts[0]!)).toBeUndefined();
    now += 1;
    expect(await freshness.resolve(apiAccounts[0]!)).toBeUndefined();
    expect(freshness.state(apiAccounts[0]!)).toBe("gone");
    now += 24 * 60 * 60_000;
    expect(await freshness.resolve(apiAccounts[0]!)).toBeUndefined();
    version = "mtime:2/content:two";
    expect(await freshness.resolve(apiAccounts[0]!)).toEqual(credential("replaced"));

    expect(client.gets).toHaveLength(4);
  });

  test("request closures consume an oauth warm cache without issuing extra gets", async () => {
    const intervals = fakeInterval();
    const client = new FakeClient(async () => credential("oauth-material"));
    const freshness = controller({ shape: "oauth", client, intervals, accounts: [apiAccounts[0]!] });
    await freshness.tick();
    const fetch = createServeFetch({
      provider: PROVIDER,
      accounts: [apiAccounts[0]!],
      client,
      freshness,
      readAuthEntry: () => tombstoneFor("oauth", PROVIDER),
      upstreamFetch: async () => new Response("ok", { status: 200 }),
    });

    await fetch("https://example.test", { headers: { Authorization: `Bearer ${sentinel(PROVIDER)}` } });
    await fetch("https://example.test", { headers: { Authorization: `Bearer ${sentinel(PROVIDER)}` } });

    expect(client.gets).toEqual([{ handle: MAIN_HANDLE, minTtlMs: 270 * 60_000 }]);
  });

  test("never logs secret-bearing values or places them in thrown errors", async () => {
    const material = "MATERIAL-CANARY";
    const sent = sentinel(PROVIDER);
    const handle = "HANDLE-CANARY";
    const connectionKey = "CONNECTION-FILE-KEY-CANARY";
    const rawBody = "RAW-BODY-CANARY";
    const authorization = `Bearer AUTHORIZATION-CANARY ${sent}`;
    const entries: unknown[] = [];
    const logger = createLogger((entry) => entries.push(entry));
    const successClient = new FakeClient(async () => credential(material));
    const success = createServeFetch({
      provider: PROVIDER,
      accounts: [{ label: "main", handle, credential_id: "id" }],
      client: successClient,
      readAuthEntry: () => tombstoneFor("api", PROVIDER),
      upstreamFetch: async () => new Response(rawBody, { status: 200 }),
      log: logger,
    });
    const authFailure = createServeFetch({
      provider: PROVIDER,
      accounts: [{ label: "main", handle, credential_id: "id" }, { label: "backup", handle: BACKUP_HANDLE, credential_id: "id2" }],
      client: new FakeClient(async (current) => credential(current === handle ? material : "backup")),
      readAuthEntry: () => tombstoneFor("api", PROVIDER),
      upstreamFetch: (() => {
        let calls = 0;
        return async () => new Response(rawBody, { status: ++calls === 1 ? 401 : 200 });
      })(),
      log: logger,
    });
    const rateLimited = createServeFetch({
      provider: PROVIDER,
      accounts: [{ label: "main", handle, credential_id: "id" }, { label: "backup", handle: BACKUP_HANDLE, credential_id: "id2" }],
      client: new FakeClient(async () => credential(material)),
      readAuthEntry: () => tombstoneFor("api", PROVIDER),
      upstreamFetch: (() => {
        let calls = 0;
        return async () => new Response(rawBody, { status: ++calls === 1 ? 429 : 200 });
      })(),
      log: logger,
    });
    const transient = createServeFetch({
      provider: PROVIDER,
      accounts: [{ label: "main", handle, credential_id: "id" }],
      client: new FakeClient(async () => { throw new Error(`${connectionKey} ${rawBody}`); }),
      readAuthEntry: () => tombstoneFor("api", PROVIDER),
      upstreamFetch: async () => new Response(rawBody, { status: 200 }),
      log: logger,
    });
    const split = createServeFetch({
      provider: PROVIDER,
      accounts: [{ label: "main", handle, credential_id: "id" }],
      client: successClient,
      readAuthEntry: () => ({ key: authorization }),
      upstreamFetch: async () => new Response(rawBody, { status: 200 }),
      log: logger,
    });
    const exhausted = createServeFetch({
      provider: PROVIDER,
      accounts: [{ label: "main", handle, credential_id: "id" }],
      client: new FakeClient(async () => { throw new ClaustrumCredentialError("not_found", "permanent", "gone"); }),
      readAuthEntry: () => tombstoneFor("api", PROVIDER),
      upstreamFetch: async () => new Response(rawBody, { status: 200 }),
      log: logger,
    });

    await success("https://example.test", { method: "POST", body: rawBody, headers: { Authorization: authorization } });
    await authFailure("https://example.test", { headers: { Authorization: authorization } });
    await rateLimited("https://example.test", { headers: { Authorization: authorization } });
    await expect(transient("https://example.test")).rejects.toThrow();
    await expect(split("https://example.test")).rejects.toThrow();
    await expect(exhausted("https://example.test")).rejects.toThrow();

    const serialized = JSON.stringify(entries);
    for (const forbidden of [material, sent, handle, connectionKey, rawBody, authorization]) {
      expect(serialized).not.toContain(forbidden);
    }
    for (const operation of [transient, split, exhausted]) {
      try {
        await operation("https://example.test");
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        for (const forbidden of [material, sent, handle, connectionKey, rawBody, authorization]) {
          expect(message).not.toContain(forbidden);
        }
      }
    }
  });

  test("unrefs the oauth timer and stops it when plugin hooks are disposed", async () => {
    const intervals = fakeInterval();
    const warmed = deferred<void>();
    const client = new FakeClient(async () => {
      warmed.resolve();
      return credential("oauth-material");
    });
    const plugin = createOpencodeClaustrumPlugin({
      handleReader: async () => ({
        version: 1,
        providers: [{ provider: PROVIDER, shape: "oauth", serve: "opencode-claustrum", accounts: [apiAccounts[0]!] }],
      }),
      authReader: async () => ({ [PROVIDER]: tombstoneFor("oauth", PROVIDER) }),
      detect: async () => ({ status: "available", schema: 1, wireVersion: 1, endpoints: [] }),
      clientFactory: async () => client as never,
      setInterval: intervals.setInterval,
      clearInterval: intervals.clearInterval,
    });
    const hooks = await plugin({} as never) as { config?: (input: unknown) => Promise<void>; dispose?: () => void };
    await hooks.config?.({ provider: { [PROVIDER]: { options: {} } } });

    expect(intervals.unrefs).toHaveLength(1);
    intervals.callbacks[0]!();
    await warmed.promise;
    expect(client.gets).toEqual([{ handle: MAIN_HANDLE, minTtlMs: 270 * 60_000 }]);
    hooks.dispose?.();
    expect(intervals.cleared).toHaveLength(1);
    intervals.callbacks[0]!();
    await Promise.resolve();
    expect(client.gets).toEqual([{ handle: MAIN_HANDLE, minTtlMs: 270 * 60_000 }]);
  });
});
