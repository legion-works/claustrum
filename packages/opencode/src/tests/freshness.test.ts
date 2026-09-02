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
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((done, fail) => { resolve = done; reject = fail; });
  return { promise, resolve, reject };
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
    // Await the returned tick promise: any future rewrite of `FreshnessController.tick()`
    // (#refreshHandleVersion + per-account #bounded/#warm chain) would otherwise change
    // the microtask count the next two `await Promise.resolve()` calls were coupled to,
    // making the assertions below quietly microtask-fragile.
    const tick = intervals.callbacks[0]!();
    await tick;

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
    expect(await freshness.resolve(apiAccounts[0]!)).toEqual(credential("fresh"));
    expect(client.gets).toEqual([
      { handle: MAIN_HANDLE, minTtlMs: undefined },
      { handle: MAIN_HANDLE, minTtlMs: undefined },
    ]);
  });

  test("discards a warm whose handle revision changed during the RPC and no concurrent resolve bumped the generation", async () => {
    // P1: a handle file change mid-RPC must not let an in-flight get repopulate the cache
    // with a credential that binds to the old handle record. The captured `version` at
    // warm-start is the only signal available before the RPC resolves; the post-RPC check
    // re-reads the handle revision and discards the result on mismatch. Without that, the
    // existing `#isCurrent` (version + generation) check accepts the stale credential:
    // a generation bump from a CONCURRENT resolve catches the same shape, but traffic
    // arriving after only the RPC settles — with no in-between resolve — would see it.
    let version = "one";
    const pending = deferred<ServedCredential>();
    let calls = 0;
    let versionReads = 0;
    const client = new FakeClient(async () => ++calls === 1 ? pending.promise : credential("after-change"));
    const freshness = controller({
      client,
      handleVersion: () => { versionReads += 1; return version; },
    });

    const first = freshness.resolve(apiAccounts[0]!);
    await Promise.resolve();
    // One read happens up-front in refreshHandleVersion; capture the baseline so the
    // post-RPC re-read is visible in the count.
    const readsAfterRefresh = versionReads;
    expect(readsAfterRefresh).toBeGreaterThanOrEqual(1);
    // Handle file changes; NO concurrent resolve that would bump the generation.
    version = "two";
    pending.resolve(credential("stale"));
    const firstResult = await first;
    await Promise.resolve();

    expect(firstResult).toBeUndefined();
    // The post-RPC check re-reads the handle revision at least once more.
    expect(versionReads).toBeGreaterThan(readsAfterRefresh);

    // Subsequent resolve observes the new version via its own refreshHandleVersion and
    // issues a fresh RPC; the cached "stale" never reaches the consumer.
    expect(await freshness.resolve(apiAccounts[0]!)).toEqual(credential("after-change"));
    expect(client.gets).toHaveLength(2);
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

  test("invalidate fences and detaches an in-flight credential get", async () => {
    const pending = deferred<ServedCredential>();
    let calls = 0;
    const client = new FakeClient(async () => ++calls === 1 ? pending.promise : credential("after-401"));
    const freshness = controller({ client });

    const first = freshness.resolve(apiAccounts[0]!);
    await Promise.resolve();
    freshness.invalidate(apiAccounts[0]!);
    pending.resolve(credential("stale-before-401"));

    expect(await first).toBeUndefined();
    expect(await freshness.resolve(apiAccounts[0]!)).toEqual(credential("after-401"));
    expect(client.gets).toHaveLength(2);
  });

  test("a stale rejection cannot poison a new revision's slot", async () => {
    // P1: an older-revision get that rejects with not_found must not flip the
    // new slot to `gone`. Without the catch-arm fence, a late permanent/not_found
    // would block the replacement credential until another handle revision.
    let version = "one";
    const pending = deferred<ServedCredential>();
    const gone = new ClaustrumCredentialError("not_found", "permanent", "gone");
    let calls = 0;
    const client = new FakeClient(async () => {
      calls += 1;
      if (calls === 1) return pending.promise;
      return credential("fresh", 9);
    });
    const freshness = controller({ client, handleVersion: () => version });

    const first = freshness.resolve(apiAccounts[0]!);
    await Promise.resolve();
    version = "two";
    await freshness.resolve(apiAccounts[0]!); // bumps generation on the same slot
    pending.reject(gone);
    await first;
    await Promise.resolve();

    // The new slot must not have inherited the rejection's `gone` state, and a
    // subsequent resolve must reach the client and return the new material.
    expect(freshness.state(apiAccounts[0]!)).not.toBe("gone");
    expect(await freshness.resolve(apiAccounts[0]!)).toEqual(credential("fresh", 9));
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

  test("expires a tick warm that times out so the next tick re-arms the account", async () => {
    // P2: a tick that times out must clear the in-flight generation; otherwise the next
    // tick reuses the same never-settling promise and the idle account never warms or
    // retries. The detached original completion is fenced by `#isCurrent` against the
    // bumped generation, so it cannot poison the slot.
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

    // Two ticks, two accounts, the deadline beats the never-resolving promise each time,
    // so each account rewarmed across the two ticks — total 4 gets, not 2.
    expect(client.gets).toEqual([
      { handle: MAIN_HANDLE, minTtlMs: 270 * 60_000 },
      { handle: BACKUP_HANDLE, minTtlMs: 270 * 60_000 },
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
