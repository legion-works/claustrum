import {
  ClaustrumCredentialError,
  type ClaustrumReporterSource,
  type ServedCredential,
} from "@cortexkit/claustrum-client";

import { CustodySplitError } from "./errors";
import { snapshotRequest } from "./request";
import { isProviderTombstone, sentinel } from "./tombstone";

export type ServeAccount = { label: string; handle: string };

export type ServeClient = {
  getCredential(handle: string): Promise<ServedCredential>;
  reportAuthFailure(input: {
    handle: string;
    providerStatus: number;
    recordVersion: number;
    reporterSource: ClaustrumReporterSource;
  }): Promise<void>;
};

export type CreateServeFetchOptions = {
  provider: string;
  accounts: ServeAccount[];
  client: ServeClient;
  readAuthEntry: () => Promise<unknown> | unknown;
  upstreamFetch: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;
  now?: () => number;
  log?: (line: string) => void;
};

type AccountRuntime = {
  label: string;
  handle: string;
  cached?: ServedCredential;
  observedAt?: number;
  cooldownUntil?: number;
  unusable?: "gone" | "reauth" | "transient";
};

export class CustodyExhaustionError extends Error {
  override name = "CustodyExhaustionError";
}

function cooldownFromRetryAfter(value: string | null, now: number): number {
  if (value && /^\d+$/.test(value.trim())) return Number(value.trim()) * 1_000;
  const date = value ? Date.parse(value) : Number.NaN;
  return Number.isFinite(date) ? Math.max(0, date - now) : 60_000;
}

async function discard(response: Response): Promise<void> {
  try {
    await response.body?.cancel();
  } catch {
  }
}

function accountState(account: AccountRuntime, now: number): string {
  if (account.unusable) return account.unusable;
  if (account.cooldownUntil !== undefined && account.cooldownUntil > now) return "cooldown";
  return "available";
}

function exhaustion(provider: string, accounts: AccountRuntime[], now: number): CustodyExhaustionError {
  const states = accounts.map((account) => `${account.label}:${accountState(account, now)}`).join(", ");
  return new CustodyExhaustionError(
    `custody accounts exhausted: provider=${provider} accounts=${states}; run ck auth migrate-opencode for gone handles`,
  );
}

function markGetFailure(error: unknown, account: AccountRuntime): void {
  if (error instanceof ClaustrumCredentialError) {
    if (error["class"] === "permanent" && error.code === "not_found") {
      account.unusable = "gone";
      return;
    }
    if (error["class"] === "auth_required") {
      account.unusable = "reauth";
      return;
    }
  }
  account.unusable = "transient";
}

async function resolveCredential(
  account: AccountRuntime,
  client: ServeClient,
  now: () => number,
): Promise<ServedCredential> {
  if (account.cached) return account.cached;
  const served = await client.getCredential(account.handle);
  account.cached = served;
  account.observedAt = now();
  account.unusable = undefined;
  return served;
}

export function createServeFetch(options: CreateServeFetchOptions) {
  const providerSentinel = sentinel(options.provider);
  const now = options.now ?? Date.now;
  const accounts: AccountRuntime[] = options.accounts.map((account) => ({ ...account }));

  return async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const snapshot = await snapshotRequest(input, init, providerSentinel);
    const authEntry = await options.readAuthEntry();
    if (!isProviderTombstone(authEntry, options.provider)) {
      throw new CustodySplitError("local credential is real while custody handles remain; migrate or restore ownership");
    }

    for (const account of accounts) {
      const currentTime = now();
      if (account.unusable === "gone" || account.unusable === "reauth") continue;
      if (account.cooldownUntil !== undefined && account.cooldownUntil > currentTime) continue;

      let served: ServedCredential;
      try {
        served = await resolveCredential(account, options.client, now);
      } catch (error) {
        markGetFailure(error, account);
        options.log?.(`provider=${options.provider} account=${account.label} state=${account.unusable}`);
        continue;
      }

      const attempt = { material: served.material, recordVersion: served.recordVersion };
      const response = await options.upstreamFetch(snapshot.withMaterial(attempt.material));
      if (response.status >= 200 && response.status < 400) return response;

      if (response.status === 401) {
        await discard(response);
        try {
          await options.client.reportAuthFailure({
            handle: account.handle,
            providerStatus: 401,
            recordVersion: attempt.recordVersion,
            reporterSource: "direct",
          });
        } finally {
          account.cached = undefined;
        }
        continue;
      }
      if (response.status === 429) {
        account.cooldownUntil = currentTime + cooldownFromRetryAfter(response.headers.get("Retry-After"), currentTime);
        await discard(response);
        continue;
      }
      if (response.status === 402) {
        account.cooldownUntil = currentTime + 60 * 60 * 1_000;
        await discard(response);
        continue;
      }
      return response;
    }

    throw exhaustion(options.provider, accounts, now());
  };
}
