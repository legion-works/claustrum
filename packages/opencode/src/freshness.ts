import { ClaustrumCredentialError, type ServedCredential } from "@cortexkit/claustrum-client";

import { CustodyOwnershipError } from "./errors";
import type { CustodyLogger } from "./log";

export type FreshnessAccount = {
  label: string;
  handle: string;
  credential_id?: string;
};

export type FreshnessClient = {
  getCredential(handle: string, minTtlMs?: number): Promise<ServedCredential>;
};

type FreshnessState = "available" | "transient" | "reauth" | "gone";

type Slot = {
  cached?: ServedCredential;
  observedAt?: number;
  cooldownUntil?: number;
  state: FreshnessState;
  inFlight?: Promise<ServedCredential | undefined>;
  generation: number;
  staleCacheWarningEmitted?: boolean;
};

type IntervalHandle = { unref?: () => unknown };

export type FreshnessControllerOptions = {
  provider?: string;
  shape: "api" | "oauth";
  accounts: FreshnessAccount[];
  client: FreshnessClient;
  minTtlMs?: number;
  now?: () => number;
  handleVersion?: () => string | Promise<string>;
  log?: CustodyLogger;
  setInterval?: (callback: () => void, ms: number) => IntervalHandle;
  clearInterval?: (handle: IntervalHandle) => void;
  setTimeout?: (callback: () => void, ms: number) => unknown;
  clearTimeout?: (handle: unknown) => void;
};

const API_FRESH_MS = 10 * 60_000;
const OAUTH_FRESH_MS = 60_000;
const OAUTH_TICK_MS = 60_000;
const DEFAULT_MIN_TTL_MS = 270 * 60_000;
const WARM_BUDGET_MS = 100;
const TRANSIENT_BACKOFF_MS = 60_000;
const REAUTH_BACKOFF_MS = 5 * 60_000;
export const DEFAULT_RETRY_AFTER_MS = 60_000;
export const PAYMENT_REQUIRED_COOLDOWN_MS = 60 * 60 * 1_000;

export class FreshnessController {
  readonly #provider?: string;
  readonly #shape: "api" | "oauth";
  readonly #accounts: FreshnessAccount[];
  readonly #client: FreshnessClient;
  readonly #minTtlMs: number;
  readonly #now: () => number;
  readonly #handleVersion?: () => string | Promise<string>;
  readonly #log?: CustodyLogger;
  readonly #setTimeout: (callback: () => void, ms: number) => unknown;
  readonly #clearTimeout: (handle: unknown) => void;
  readonly #slots = new Map<string, Slot>();
  #version: string | undefined;
  #timer: IntervalHandle | undefined;
  #disposed = false;

  constructor(options: FreshnessControllerOptions) {
    this.#provider = options.provider;
    this.#shape = options.shape;
    this.#accounts = options.accounts.map((account) => ({ ...account }));
    this.#client = options.client;
    this.#minTtlMs = options.minTtlMs ?? DEFAULT_MIN_TTL_MS;
    this.#now = options.now ?? Date.now;
    this.#handleVersion = options.handleVersion;
    this.#log = options.log;
    this.#setTimeout = options.setTimeout ?? globalThis.setTimeout;
    this.#clearTimeout = options.clearTimeout ?? ((timer) => globalThis.clearTimeout(timer as ReturnType<typeof setTimeout>));
    for (const account of this.#accounts) this.#slots.set(account.handle, { state: "available", generation: 0 });
    if (this.#shape === "oauth") {
      const set = options.setInterval ?? ((callback, ms) => globalThis.setInterval(callback, ms) as unknown as IntervalHandle);
      const clear = options.clearInterval ?? ((timer) => globalThis.clearInterval(timer as unknown as ReturnType<typeof setInterval>));
      this.#timer = set(() => {
        void this.tick().catch((error) => {
          this.#log?.error({
            provider: this.#provider,
            errorClass: error instanceof Error ? error.name : "FreshnessTickError",
            errorMessage: "credential freshness tick failed",
          });
        });
      }, OAUTH_TICK_MS);
      this.#timer.unref?.();
      this.#clearInterval = clear;
    }
  }

  #clearInterval?: (handle: IntervalHandle) => void;

  state(account: FreshnessAccount): FreshnessState | "cooldown" {
    const slot = this.#slot(account);
    if (slot.state !== "available") return slot.state;
    if (slot.cooldownUntil !== undefined && slot.cooldownUntil > this.#now()) return "cooldown";
    return "available";
  }

  async resolve(account: FreshnessAccount): Promise<ServedCredential | undefined> {
    await this.#refreshHandleVersion();
    const slot = this.#slot(account);
    if (slot.state === "transient" && this.#isFresh(slot)) {
      if (!slot.staleCacheWarningEmitted) {
        slot.staleCacheWarningEmitted = true;
        this.#log?.warn({
          provider: this.#provider,
          label: account.label,
          credentialId: account.credential_id,
          state: "transient",
          errorCode: "serving_cached",
        });
      }
      return slot.cached;
    }
    if (!this.#canWarm(slot)) return undefined;
    if (this.#isFresh(slot)) return slot.cached;
    return this.#bounded(account, this.#warm(account, false));
  }

  async tick(): Promise<void> {
    if (this.#disposed || this.#shape !== "oauth") return;
    await this.#refreshHandleVersion();
    await Promise.all(this.#accounts.map(async (account) => {
      const slot = this.#slot(account);
      // Expire on timeout: a hung `credential.get` must not pin the in-flight generation
      // for every later tick -- the only consequence of leaving it bound is that the
      // idle account never warms or retries. The detached original completion is already
      // fenced by `#isCurrent` against the bumped generation, so it cannot poison the slot.
      if (this.#canWarm(slot)) await this.#bounded(account, this.#warm(account, true), true);
    }));
  }

  invalidate(account: FreshnessAccount): void {
    const slot = this.#slot(account);
    slot.cached = undefined;
    slot.observedAt = undefined;
  }

  cooldown(account: FreshnessAccount, durationMs: number): number {
    const slot = this.#slot(account);
    slot.cooldownUntil = Math.max(slot.cooldownUntil ?? 0, this.#now() + durationMs);
    this.#log?.warn({
      provider: this.#provider,
      label: account.label,
      credentialId: account.credential_id,
      state: "cooldown",
      cooldownUntil: slot.cooldownUntil,
    });
    return slot.cooldownUntil;
  }

  dispose(): void {
    this.#disposed = true;
    if (this.#timer) this.#clearInterval?.(this.#timer);
    this.#timer = undefined;
  }

  #slot(account: FreshnessAccount): Slot {
    const slot = this.#slots.get(account.handle);
    if (!slot) throw new Error("account is not managed by this freshness controller");
    return slot;
  }

  #isFresh(slot: Slot): boolean {
    if (!slot.cached || slot.observedAt === undefined) return false;
    return this.#now() - slot.observedAt < (this.#shape === "api" ? API_FRESH_MS : OAUTH_FRESH_MS);
  }

  #canWarm(slot: Slot): boolean {
    if (slot.state === "gone") return false;
    if (slot.cooldownUntil !== undefined && slot.cooldownUntil > this.#now()) return false;
    return true;
  }

  #warm(account: FreshnessAccount, force: boolean): Promise<ServedCredential | undefined> {
    const slot = this.#slot(account);
    if (!force && this.#isFresh(slot)) return Promise.resolve(slot.cached);
    if (slot.inFlight) return slot.inFlight;
    const minTtlMs = this.#shape === "oauth" ? this.#minTtlMs : undefined;
    const version = this.#version;
    const generation = ++slot.generation;
    const inFlight = this.#client.getCredential(account.handle, minTtlMs)
      .then(async (served) => {
        // Re-read the handle revision after the RPC completes: a handle file change
        // mid-RPC means the captured `version` is stale and the served credential may
        // bind to a different handle record. `#isCurrent` only compares the captured
        // version against `this.#version`, which doesn't move until the next
        // `refreshHandleVersion` runs — so without this check, a quiet window between
        // the RPC settling and the next resolve would accept the stale material.
        if (this.#handleVersion) {
          let current: string;
          try {
            current = await this.#handleVersion();
          } catch {
            // Failed re-read is treated as a version mismatch: refuse to cache.
            return undefined;
          }
          if (current !== version) return undefined;
        }
        if (!this.#isCurrent(slot, version, generation)) return undefined;
        slot.cached = served;
        slot.observedAt = this.#now();
        slot.cooldownUntil = undefined;
        slot.state = "available";
        slot.staleCacheWarningEmitted = false;
        return served;
      })
      .catch((error: unknown) => {
        if (this.#isCurrent(slot, version, generation)) this.#markFailure(account, slot, error);
        return undefined;
      })
      .finally(() => {
        if (slot.inFlight === inFlight) slot.inFlight = undefined;
      });
    slot.inFlight = inFlight;
    return inFlight;
  }

  #isCurrent(slot: Slot, version: string | undefined, generation: number): boolean {
    return version === this.#version && generation === slot.generation;
  }

  async #bounded(account: FreshnessAccount, promise: Promise<ServedCredential | undefined>, expire = true): Promise<ServedCredential | undefined> {
    let timeout: unknown;
    const deadline = new Promise<void>((resolve) => {
      timeout = this.#setTimeout(() => resolve(), WARM_BUDGET_MS);
    });
    const result = await Promise.race([
      promise.then((served) => ({ kind: "completed" as const, served })),
      deadline.then(() => ({ kind: "timeout" as const })),
    ]);
    if (timeout !== undefined) this.#clearTimeout(timeout);
    if (result.kind === "timeout") {
      const slot = this.#slot(account);
      if (expire && slot.inFlight === promise) {
        slot.inFlight = undefined;
        slot.generation += 1;
      }
      this.#log?.warn({ provider: this.#provider, state: "transient", errorClass: "credential_warm", errorCode: "timeout" });
    }
    return result.kind === "completed" ? result.served : undefined;
  }

  #markFailure(account: FreshnessAccount, slot: Slot, error: unknown): void {
    const now = this.#now();
    let errorClass = error instanceof ClaustrumCredentialError ? error["class"] : "transient";
    let errorCode = error instanceof ClaustrumCredentialError ? error.code : "transport_error";
    if (error instanceof ClaustrumCredentialError && error["class"] === "permanent" && error.code === "not_found") {
      slot.state = "gone";
      slot.cooldownUntil = undefined;
    } else if (error instanceof ClaustrumCredentialError && error["class"] === "auth_required") {
      slot.state = "reauth";
      slot.cooldownUntil = now + REAUTH_BACKOFF_MS;
    } else {
      slot.state = "transient";
      slot.cooldownUntil = now + TRANSIENT_BACKOFF_MS;
      errorClass = "transient";
      errorCode = errorCode || "transport_error";
    }
    this.#log?.warn({
      provider: this.#provider,
      label: account.label,
      credentialId: account.credential_id,
      state: slot.state,
      cooldownUntil: slot.cooldownUntil,
      errorClass,
      errorCode,
    });
  }

  async #refreshHandleVersion(): Promise<void> {
    if (!this.#handleVersion) return;
    try {
      const current = await this.#handleVersion();
      if (this.#version !== undefined && current !== this.#version) {
        for (const slot of this.#slots.values()) {
           slot.cached = undefined;
           slot.observedAt = undefined;
           slot.inFlight = undefined;
           slot.cooldownUntil = undefined;
           slot.state = "available";
           slot.staleCacheWarningEmitted = false;
        }
      }
      this.#version = current;
    } catch (error) {
      const refusal = new CustodyOwnershipError(
        `could not verify custody handle ownership: ${error instanceof Error ? error.name : "unknown error"}`,
      );
      this.#log?.error({ provider: this.#provider, errorClass: refusal.name, errorMessage: refusal.message });
      throw refusal;
    }
  }
}
