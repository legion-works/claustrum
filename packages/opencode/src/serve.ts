import {
  type ClaustrumReporterSource,
  type ServedCredential,
} from "@cortexkit/claustrum-client";

import { CustodyAuthReadError, CustodyExhaustionError, CustodyOwnershipError, CustodyRedirectRefusedError, CustodyRequestError, CustodySplitError } from "./errors";
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
  verifyOwnership?: () => Promise<void>;
  log?: CustodyLogger;
};

type AccountRuntime = {
  account: ServeAccount;
};

const REPORT_BUDGET_MS = 100;

async function reportWithinBudget(report: Promise<void>, onFailure: (errorClass: string, errorCode: string) => void): Promise<void> {
  let timeout: ReturnType<typeof setTimeout> | undefined;
  const completed = await Promise.race([
    report.then(
      () => true,
      (error) => {
        onFailure(error instanceof Error ? error.name : "ReportError", "failed");
        return true;
      },
    ),
    new Promise<false>((resolve) => { timeout = setTimeout(() => resolve(false), REPORT_BUDGET_MS); }),
  ]);
  if (timeout !== undefined) clearTimeout(timeout);
  if (!completed) onFailure("ReportTimeout", "timeout");
}

function cooldownFromRetryAfter(value: string | null, now: number): number {
  if (value && /^\d+$/.test(value.trim())) {
    const milliseconds = Number(value.trim()) * 1_000;
    return Number.isFinite(milliseconds) ? milliseconds : DEFAULT_RETRY_AFTER_MS;
  }
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
    let snapshot;
    try {
      snapshot = await snapshotRequest(input, init, providerSentinel);
    } catch (error) {
      const refusal = new CustodyRequestError(
        `could not prepare custody request: ${error instanceof Error ? error.name : String(error)}`,
      );
      options.log?.error({ provider: options.provider, errorClass: refusal.name, errorMessage: refusal.message });
      throw refusal;
    }
    let authEntry: unknown;
    try {
      authEntry = await options.readAuthEntry();
    } catch (error) {
      const refusal = new CustodyAuthReadError(
        `could not read OpenCode auth entry: ${error instanceof Error ? error.name : "unknown error"}`,
      );
      options.log?.error({ provider: options.provider, errorClass: refusal.name, errorMessage: refusal.message });
      throw refusal;
    }
    if (!isProviderTombstone(authEntry, options.provider)) {
      const refusal = new CustodySplitError("local credential is real while custody handles remain; migrate or restore ownership");
      options.log?.error({ provider: options.provider, errorClass: refusal.name, errorMessage: refusal.message });
      throw refusal;
    }
    if (options.verifyOwnership) {
      try {
        await options.verifyOwnership();
      } catch (error) {
        const refusal = error instanceof CustodyOwnershipError
          ? error
          : new CustodyOwnershipError(
            `could not verify custody handle ownership: ${error instanceof Error ? error.name : "unknown error"}`,
          );
        options.log?.error({ provider: options.provider, errorClass: refusal.name, errorMessage: refusal.message });
        throw refusal;
      }
    }

    for (const { account } of accounts) {
      const served = await freshness.resolve(account);
      if (!served) continue;

      const attempt = { material: served.material, recordVersion: served.recordVersion };
      let target: URL | undefined;
      let methodOverride: string | undefined;
      for (let hop = 0; hop <= 5; hop += 1) {
        let forwarded: Request;
        try {
          forwarded = snapshot.withMaterial(attempt.material, target, methodOverride);
        } catch (error) {
          const refusal = new CustodyRequestError(
            `could not substitute custody credential: ${error instanceof Error ? error.name : String(error)}`,
          );
          options.log?.error({ provider: options.provider, errorClass: refusal.name, errorMessage: refusal.message });
          throw refusal;
        }
        let response: Response;
        try {
          response = await options.upstreamFetch(forwarded);
        } catch (error) {
          options.log?.error({
            provider: options.provider,
            errorClass: error instanceof Error ? error.name : "UpstreamFetchError",
            errorMessage: "upstream request failed",
          });
          throw new CustodyRequestError("upstream request failed");
        }
        if (response.status < 300 || response.status >= 400 || ![301, 302, 303, 307, 308].includes(response.status)) {
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
              await reportWithinBudget(
                options.client.reportAuthFailure({
                  handle: account.handle,
                  providerStatus: 401,
                  recordVersion: attempt.recordVersion,
                  reporterSource: "direct",
                }),
                (errorClass, errorCode) => options.log?.warn({
                  provider: options.provider,
                  label: account.label,
                  credentialId: account.credential_id,
                  errorClass,
                  errorCode,
                }),
              );
            } finally {
              freshness.invalidate(account);
            }
            break;
          }
          if (response.status === 429) {
            freshness.cooldown(account, cooldownFromRetryAfter(response.headers.get("Retry-After"), now()));
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
        let fromOrigin: string;
        let next: URL;
        try {
          fromOrigin = new URL(forwarded.url).origin;
          next = new URL(location, forwarded.url);
        } catch (error) {
          await discard(response);
          const refusal = new CustodyRequestError(
            `could not validate custody redirect: ${error instanceof Error ? error.name : String(error)}`,
          );
          options.log?.error({ provider: options.provider, errorClass: refusal.name, errorMessage: refusal.message });
          throw refusal;
        }
        if (next.origin !== fromOrigin) {
          await discard(response);
          const refusal = new CustodyRedirectRefusedError(options.provider, fromOrigin, next.origin);
          options.log?.error({ provider: options.provider, errorClass: refusal.name, errorMessage: refusal.message });
          throw refusal;
        }
        if (hop === 5) {
          await discard(response);
          const refusal = new CustodyRedirectRefusedError(options.provider, fromOrigin, next.origin);
          options.log?.error({ provider: options.provider, errorClass: refusal.name, errorMessage: refusal.message });
          throw refusal;
        }
        await discard(response);
        target = next;
        methodOverride = (response.status === 303 && forwarded.method !== "GET" && forwarded.method !== "HEAD") ||
          ((response.status === 301 || response.status === 302) && forwarded.method === "POST")
          ? "GET"
          : methodOverride;
      }

      continue;
    }

    const refusal = exhaustion(options.provider, accounts, freshness);
    options.log?.error({ provider: options.provider, errorClass: refusal.name, errorMessage: refusal.message });
    throw refusal;
  };
}
