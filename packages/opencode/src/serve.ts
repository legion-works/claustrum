import {
  type ClaustrumReporterSource,
  type ServedCredential,
} from "@cortexkit/claustrum-client";

import { CustodySplitError } from "./errors";
import { FreshnessController, type FreshnessAccount } from "./freshness";
import type { CustodyLogger } from "./log";
import { snapshotRequest } from "./request";
import { isProviderTombstone, sentinel } from "./tombstone";

export type ServeAccount = FreshnessAccount;

export type ServeClient = {
  getCredential(handle: string, minTtlMs?: number): Promise<ServedCredential>;
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
  shape?: "api" | "oauth";
  freshness?: FreshnessController;
  log?: CustodyLogger;
};

type AccountRuntime = {
  account: ServeAccount;
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

function exhaustion(provider: string, accounts: AccountRuntime[], freshness: FreshnessController): CustodyExhaustionError {
  const states = accounts.map(({ account }) => `${account.label}:${freshness.state(account)}`).join(", ");
  return new CustodyExhaustionError(
    `custody accounts exhausted: provider=${provider} accounts=${states}; run ck auth migrate-opencode for gone handles`,
  );
}

export function createServeFetch(options: CreateServeFetchOptions) {
  const providerSentinel = sentinel(options.provider);
  const now = options.now ?? Date.now;
  const accounts: AccountRuntime[] = options.accounts.map((account) => ({ account }));
  const freshness = options.freshness ?? new FreshnessController({
    provider: options.provider,
    shape: options.shape ?? "api",
    accounts: options.accounts,
    client: options.client,
    now,
    log: options.log,
  });

  return async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const snapshot = await snapshotRequest(input, init, providerSentinel);
    const authEntry = await options.readAuthEntry();
    if (!isProviderTombstone(authEntry, options.provider)) {
      throw new CustodySplitError("local credential is real while custody handles remain; migrate or restore ownership");
    }

    for (const { account } of accounts) {
      const currentTime = now();
      const served = await freshness.resolve(account);
      if (!served) continue;

      const attempt = { material: served.material, recordVersion: served.recordVersion };
      const response = await options.upstreamFetch(snapshot.withMaterial(attempt.material));
      if (response.status >= 200 && response.status < 400) return response;

      if (response.status === 401) {
        options.log?.warn({
          provider: options.provider,
          label: account.label,
          credentialId: account.credential_id,
          recordVersion: attempt.recordVersion,
          httpStatus: 401,
        });
        await discard(response);
        try {
          await options.client.reportAuthFailure({
            handle: account.handle,
            providerStatus: 401,
            recordVersion: attempt.recordVersion,
            reporterSource: "direct",
          });
        } finally {
          freshness.invalidate(account);
        }
        continue;
      }
      if (response.status === 429) {
        freshness.cooldown(account, cooldownFromRetryAfter(response.headers.get("Retry-After"), currentTime));
        options.log?.warn({
          provider: options.provider,
          label: account.label,
          credentialId: account.credential_id,
          httpStatus: 429,
        });
        await discard(response);
        continue;
      }
      if (response.status === 402) {
        freshness.cooldown(account, 60 * 60 * 1_000);
        options.log?.warn({
          provider: options.provider,
          label: account.label,
          credentialId: account.credential_id,
          httpStatus: 402,
        });
        await discard(response);
        continue;
      }
      return response;
    }

    throw exhaustion(options.provider, accounts, freshness);
  };
}
