import {
  type ClaustrumReporterSource,
  type ServedCredential,
} from "@cortexkit/claustrum-client";

import { CustodyAuthReadError, CustodyExhaustionError, CustodyRedirectRefusedError, CustodySplitError } from "./errors";
import {
  DEFAULT_RETRY_AFTER_MS,
  FreshnessController,
  PAYMENT_REQUIRED_COOLDOWN_MS,
  type FreshnessAccount,
} from "./freshness";
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

const REPORT_BUDGET_MS = 100;

async function reportWithinBudget(report: Promise<void>): Promise<void> {
  let timeout: ReturnType<typeof setTimeout> | undefined;
  await Promise.race([
    report.catch(() => {}),
    new Promise<void>((resolve) => { timeout = setTimeout(resolve, REPORT_BUDGET_MS); }),
  ]);
  if (timeout !== undefined) clearTimeout(timeout);
}

function cooldownFromRetryAfter(value: string | null, now: number): number {
  if (value && /^\d+$/.test(value.trim())) return Number(value.trim()) * 1_000;
  const date = value ? Date.parse(value) : Number.NaN;
  return Number.isFinite(date) ? Math.max(0, date - now) : DEFAULT_RETRY_AFTER_MS;
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
    let authEntry: unknown;
    try {
      authEntry = await options.readAuthEntry();
    } catch (error) {
      throw new CustodyAuthReadError(
        `could not read OpenCode auth entry: ${error instanceof Error ? error.name : "unknown error"}`,
      );
    }
    if (!isProviderTombstone(authEntry, options.provider)) {
      throw new CustodySplitError("local credential is real while custody handles remain; migrate or restore ownership");
    }

    for (const { account } of accounts) {
      const currentTime = now();
      const served = await freshness.resolve(account);
      if (!served) continue;

      const attempt = { material: served.material, recordVersion: served.recordVersion };
      let target: URL | undefined;
      let methodOverride: string | undefined;
      for (let hop = 0; hop <= 5; hop += 1) {
        const forwarded = snapshot.withMaterial(attempt.material, target, methodOverride);
        const response = await options.upstreamFetch(forwarded);
        if (response.status < 300 || response.status >= 400) {
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
              await reportWithinBudget(options.client.reportAuthFailure({
                handle: account.handle,
                providerStatus: 401,
                recordVersion: attempt.recordVersion,
                reporterSource: "direct",
              }));
            } finally {
              freshness.invalidate(account);
            }
            break;
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
            break;
          }
          if (response.status === 402) {
            freshness.cooldown(account, PAYMENT_REQUIRED_COOLDOWN_MS);
            options.log?.warn({
              provider: options.provider,
              label: account.label,
              credentialId: account.credential_id,
              httpStatus: 402,
            });
            await discard(response);
            break;
          }
          return response;
        }
        const location = response.headers.get("Location");
        if (!location) return response;
        const fromOrigin = new URL(forwarded.url).origin;
        const next = new URL(location, forwarded.url);
        if (next.origin !== fromOrigin) {
          await discard(response);
          throw new CustodyRedirectRefusedError(options.provider, fromOrigin, next.origin);
        }
        if (hop === 5) {
          await discard(response);
          throw new CustodyRedirectRefusedError(options.provider, fromOrigin, next.origin);
        }
        await discard(response);
        target = next;
        methodOverride = response.status === 303 ||
          ((response.status === 301 || response.status === 302) && forwarded.method === "POST")
          ? "GET"
          : methodOverride;
      }

      continue;
    }

    throw exhaustion(options.provider, accounts, freshness);
  };
}
