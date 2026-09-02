import { readFile, stat } from "node:fs/promises";
import { join } from "node:path";

import { ClaustrumClient, detectClaustrumConnection } from "@cortexkit/claustrum-client";
import type { Plugin } from "@opencode-ai/plugin";

import { AuthFileValidationError, CustodyOrphanError, CustodySplitError, HandleFileValidationError } from "./errors";
import { FreshnessController } from "./freshness";
import { defaultHandleFilePath, handleFileRevision, OUR_PLUGIN_ID, readHandleFile, type OpenCodeHandleFileV1 } from "./handles";
import { createLogger, serializedLogSink, type CustodyLogger, type LogSink } from "./log";
import { createServeFetch, type ServeClient } from "./serve";
import { isProviderTombstone, sentinel } from "./tombstone";

type ConfigProvider = { options?: Record<string, unknown> };
type MutableConfig = { provider?: Record<string, ConfigProvider> };
const AUTH_FILE_MAX_BYTES = 1024 * 1024;

export type ConfigHookDependencies = {
  handleReader?: (path: string) => Promise<OpenCodeHandleFileV1>;
  authReader?: (path: string) => Promise<Record<string, unknown>>;
  log?: (line: string) => void;
  logSink?: LogSink;
  detect?: typeof detectClaustrumConnection;
  clientFactory?: typeof ClaustrumClient.connect;
  fetch?: typeof globalThis.fetch;
  now?: () => number;
  oauthMinTtlMs?: number;
  handleVersionReader?: (path: string) => Promise<string>;
  setInterval?: (callback: () => void, ms: number) => { unref?: () => unknown };
  clearInterval?: (timer: { unref?: () => unknown }) => void;
};

function defaultAuthPath(env: NodeJS.ProcessEnv = process.env): string {
  const dataHome = env.XDG_DATA_HOME || (env.HOME ? join(env.HOME, ".local", "share") : ".local/share");
  return join(dataHome, "opencode", "auth.json");
}

async function readAuth(path: string): Promise<Record<string, unknown>> {
  try {
    if ((await stat(path)).size > AUTH_FILE_MAX_BYTES) {
      throw new AuthFileValidationError("auth file exceeds 1 MiB");
    }
    const value: unknown = JSON.parse(await readFile(path, "utf8"));
    return value && typeof value === "object" && !Array.isArray(value)
      ? value as Record<string, unknown>
      : {};
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return {};
    throw error;
  }
}

function logError(log: CustodyLogger, error: Error, provider: string) {
  log.error({
    provider,
    errorClass: error.name,
    errorCode: (error as NodeJS.ErrnoException).code,
  });
}

export function createOpencodeClaustrumPlugin(dependencies: ConfigHookDependencies = {}): Plugin {
  const handleReader = dependencies.handleReader ?? readHandleFile;
  const authReader = dependencies.authReader ?? readAuth;
  const log = createLogger(dependencies.logSink ?? (dependencies.log ? serializedLogSink(dependencies.log) : undefined));
  const detection = dependencies.detect ?? detectClaustrumConnection;
  const clientFactory = dependencies.clientFactory ?? ClaustrumClient.connect;
  const upstreamFetch = dependencies.fetch ?? globalThis.fetch;
  const handleVersionReader = dependencies.handleVersionReader
    ?? (dependencies.handleReader ? async (path: string) => JSON.stringify(await handleReader(path)) : handleFileRevision);
  let connected: Promise<ClaustrumClient> | undefined;
  const client: ServeClient = {
    async getCredential(handle, minTtlMs) {
      return (await connect()).getCredential(handle, minTtlMs);
    },
    async reportAuthFailure(input) {
      await (await connect()).reportAuthFailure(input);
    },
  };

  async function connect(): Promise<ClaustrumClient> {
    connected ??= (async () => {
      const result = await detection();
      if (result.status !== "available") throw new Error(`Claustrum connection ${result.status}`);
      return clientFactory();
    })();
    return connected;
  }

  return async () => {
    let controllers: FreshnessController[] = [];
    return {
      config: async (input) => {
        for (const controller of controllers) controller.dispose();
        controllers = [];
        let handles: OpenCodeHandleFileV1;
        try {
          handles = await handleReader(defaultHandleFilePath());
        } catch (error) {
          const typed = error instanceof HandleFileValidationError
            ? error
            : new HandleFileValidationError(error instanceof Error ? error.message : String(error));
          logError(log, typed, "handle-file");
          return;
        }

        let auth: Record<string, unknown>;
        try {
          auth = await authReader(defaultAuthPath());
        } catch (error) {
          log.error({
            errorClass: error instanceof Error ? error.name : "AuthReadError",
            errorCode: (error as NodeJS.ErrnoException).code,
          });
          return;
        }

        const byProvider = new Map(handles.providers.map((provider) => [provider.provider, provider]));
        const providers = [...byProvider.keys()];
        for (const provider of Object.keys(auth)) {
          if (!byProvider.has(provider) && isProviderTombstone(auth[provider], provider)) providers.push(provider);
        }

        const cfg = input as MutableConfig;
        cfg.provider ??= Object.create(null) as Record<string, ConfigProvider>;
        for (const provider of providers) {
          const handle = byProvider.get(provider);
            const entry = Object.hasOwn(auth, provider) ? auth[provider] : undefined;
          const tombstone = isProviderTombstone(entry, provider);
          const owner = handle?.serve;

          if (!tombstone) {
            if (owner === OUR_PLUGIN_ID) {
              if (entry === undefined) {
                logError(log, new CustodyOrphanError("handle entry has no auth.json counterpart; run ck auth migrate-opencode"), provider);
                continue;
              }
              const error = new CustodySplitError(
                `local credential is real while custody handles remain; run ck auth migrate-opencode --provider ${provider} to re-tombstone, or ck auth migrate-opencode --restore ${provider} to use the local credential`,
              );
              logError(log, error, provider);
              const configured = Object.hasOwn(cfg.provider, provider)
                ? cfg.provider[provider]!
                : (cfg.provider[provider] = {});
              configured.options = {
                ...(configured.options ?? {}),
                fetch: async () => { throw error; },
              };
            }
            continue;
          }
          if (owner !== OUR_PLUGIN_ID) {
            if (owner) log.debug({ provider, errorClass: "other_owner", errorCode: owner });
            else logError(log, new CustodyOrphanError("tombstone has no serving handle; run ck auth migrate-opencode"), provider);
            continue;
          }

          const configured = Object.hasOwn(cfg.provider, provider)
            ? cfg.provider[provider]!
            : (cfg.provider[provider] = {});
          const freshness = new FreshnessController({
            provider,
            shape: handle!.shape,
            accounts: handle!.accounts,
            client,
            minTtlMs: dependencies.oauthMinTtlMs,
            now: dependencies.now,
            handleVersion: () => handleVersionReader(defaultHandleFilePath()),
            log,
            setInterval: dependencies.setInterval,
            clearInterval: dependencies.clearInterval,
          });
          controllers.push(freshness);
          configured.options = {
            ...(configured.options ?? {}),
            apiKey: sentinel(provider),
            fetch: createServeFetch({
              provider,
              accounts: handle!.accounts,
              client,
              shape: handle!.shape,
              freshness,
              readAuthEntry: async () => (await authReader(defaultAuthPath()))[provider],
              upstreamFetch,
              log,
            }),
          };
        }
      },
      dispose: async () => {
        for (const controller of controllers) controller.dispose();
        controllers = [];
      },
    };
  };
}

export const OpencodeClaustrumPlugin = createOpencodeClaustrumPlugin();

export default OpencodeClaustrumPlugin;
