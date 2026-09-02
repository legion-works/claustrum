import { readFile } from "node:fs/promises";
import { join } from "node:path";

import { ClaustrumClient, detectClaustrumConnection } from "@cortexkit/claustrum-client";
import type { Plugin } from "@opencode-ai/plugin";

import { CustodyOrphanError, CustodySplitError, HandleFileValidationError } from "./errors";
import { FreshnessController } from "./freshness";
import { defaultHandleFilePath, handleFileRevision, OUR_PLUGIN_ID, readHandleFile, type OpenCodeHandleFileV1 } from "./handles";
import { createLogger, serializedLogSink, type CustodyLogger, type LogSink } from "./log";
import { createServeFetch, type ServeClient } from "./serve";
import { isProviderTombstone, sentinel } from "./tombstone";

type ConfigProvider = { options?: Record<string, unknown> };
type MutableConfig = { provider?: Record<string, ConfigProvider> };

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
      cfg.provider ??= {};
      for (const provider of providers) {
        const handle = byProvider.get(provider);
        const entry = auth[provider];
        const tombstone = isProviderTombstone(entry, provider);
        const owner = handle?.serve;

        if (!tombstone) {
          if (owner === OUR_PLUGIN_ID) logError(log, new CustodySplitError("local credential is real; migrate or restore ownership"), provider);
          continue;
        }
        if (owner !== OUR_PLUGIN_ID) {
          if (owner) log.debug({ provider, errorClass: "other_owner" });
          else logError(log, new CustodyOrphanError("tombstone has no serving handle; run ck auth migrate-opencode"), provider);
          continue;
        }

        const configured = cfg.provider[provider] ??= {};
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
