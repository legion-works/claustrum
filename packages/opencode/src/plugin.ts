import { readFile } from "node:fs/promises";
import { join } from "node:path";

import { ClaustrumClient, detectClaustrumConnection } from "@cortexkit/claustrum-client";
import type { Plugin } from "@opencode-ai/plugin";

import { CustodyOrphanError, CustodySplitError, HandleFileValidationError } from "./errors";
import { defaultHandleFilePath, OUR_PLUGIN_ID, readHandleFile, type OpenCodeHandleFileV1 } from "./handles";
import { createServeFetch, type ServeClient } from "./serve";
import { isProviderTombstone, sentinel } from "./tombstone";

type ConfigProvider = { options?: Record<string, unknown> };
type MutableConfig = { provider?: Record<string, ConfigProvider> };

export type ConfigHookDependencies = {
  handleReader?: (path: string) => Promise<OpenCodeHandleFileV1>;
  authReader?: (path: string) => Promise<Record<string, unknown>>;
  log?: (line: string) => void;
  detect?: typeof detectClaustrumConnection;
  clientFactory?: typeof ClaustrumClient.connect;
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

function logError(log: (line: string) => void, error: Error, provider: string) {
  log(`${error.name}: provider=${provider} ${error.message}`);
}

export function createOpencodeClaustrumPlugin(dependencies: ConfigHookDependencies = {}): Plugin {
  const handleReader = dependencies.handleReader ?? readHandleFile;
  const authReader = dependencies.authReader ?? readAuth;
  const log = dependencies.log ?? ((line: string) => console.error(line));
  // Config must not open the vault; the request path owns connection lifecycle.
  const detection = dependencies.detect ?? detectClaustrumConnection;
  const clientFactory = dependencies.clientFactory ?? ClaustrumClient.connect;
  let connected: Promise<ClaustrumClient> | undefined;
  const client: ServeClient = {
    async getCredential(handle) {
      return (await connect()).getCredential(handle);
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

  return async () => ({
    config: async (input) => {
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
        log(`auth read failed: ${error instanceof Error ? error.message : String(error)}`);
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
          if (owner) log(`debug: provider=${provider} owner=${owner} tombstone left for owner`);
          else logError(log, new CustodyOrphanError("tombstone has no serving handle; run ck auth migrate-opencode"), provider);
          continue;
        }

        const configured = cfg.provider[provider] ??= {};
        configured.options = {
          ...(configured.options ?? {}),
          apiKey: sentinel(provider),
          fetch: createServeFetch({
            provider,
            accounts: handle!.accounts,
            client,
            readAuthEntry: async () => (await authReader(defaultAuthPath()))[provider],
            upstreamFetch: globalThis.fetch,
            log,
          }),
        };
      }
    },
  });
}

export const OpencodeClaustrumPlugin = createOpencodeClaustrumPlugin();
