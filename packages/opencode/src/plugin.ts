import { createReadStream } from "node:fs";
import { readFile, stat } from "node:fs/promises";
import { join } from "node:path";

import { ClaustrumClient, detectClaustrumConnection } from "@cortexkit/claustrum-client";
import type { Plugin } from "@opencode-ai/plugin";

import {
  AuthFileValidationError,
  CustodyAuthReadError,
  CustodyNativeRuntimeError,
  CustodyOwnershipError,
  CustodyOrphanError,
  CustodySplitError,
  HandleFileValidationError,
} from "./errors";
import { FreshnessController } from "./freshness";
import { defaultHandleFilePath, handleFileRevision, OUR_PLUGIN_ID, readHandleFile, type OpenCodeHandleFileV1 } from "./handles";
import { createLogger, serializedLogSink, type CustodyLogger, type LogSink } from "./log";
import { createServeFetch, type ServeClient } from "./serve";
import { isProviderTombstone, sentinel, TOMBSTONE_PREFIX } from "./tombstone";

type ConfigProvider = { options?: Record<string, unknown> };
type MutableConfig = { provider?: Record<string, ConfigProvider> };
const AUTH_FILE_MAX_BYTES = 1024 * 1024;
const AUTH_SCAN_CHUNK_BYTES = 64 * 1024;
const AUTH_SCAN_CARRY_BYTES = TOMBSTONE_PREFIX.length + 64;
const SCANNED_PROVIDER_ID = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const FORBIDDEN_PROVIDER_IDS = new Set(["__proto__", "constructor", "prototype"]);

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

async function readAuthFile(path: string): Promise<Record<string, unknown>> {
  try {
    if ((await stat(path)).size > AUTH_FILE_MAX_BYTES) {
      throw new AuthFileValidationError("auth file exceeds 1 MiB");
    }
    let value: unknown;
    try {
      value = JSON.parse(await readFile(path, "utf8"));
    } catch (error) {
      if (error instanceof AuthFileValidationError) throw error;
      throw new AuthFileValidationError(`auth file contains invalid JSON: ${error instanceof Error ? error.message : String(error)}`);
    }
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw new AuthFileValidationError("auth file must contain an object");
    }
    return value as Record<string, unknown>;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return {};
    if (error instanceof AuthFileValidationError) throw error;
    throw new AuthFileValidationError(`cannot read auth file: ${error instanceof Error ? error.message : String(error)}`);
  }
}

async function readAuth(path: string, reader: (path: string) => Promise<Record<string, unknown>>): Promise<Record<string, unknown>> {
  const content = process.env.OPENCODE_AUTH_CONTENT;
  if (content) {
    try {
      const value: unknown = JSON.parse(content);
      if (!value || typeof value !== "object" || Array.isArray(value)) {
        return {};
      }
      return value as Record<string, unknown>;
    } catch {}
  }
  return reader(path);
}

// Raw-byte scan for self-describing sentinels when the auth source cannot be parsed. Two
// deliberate limits, coupled: (1) a JSON-escaped sentinel (`\u0063laustrum-…`) is not found, and
// (2) no hits means no refusals so a never-migrated user with a large auth.json keeps working —
// both are the same no-hit branch; closing (1) breaks (2). A mis-keyed sentinel refuses the
// provider it NAMES, not the entry that carries it; tolerable only because the sentinel is
// non-secret (availability loss, nothing exposed). Rationale: docs/opencode-custody-design.md.
function scanTombstones(source: string, onHit: (provider: string) => void, allowTrailing = false) {
  let index = 0;
  while ((index = source.indexOf(TOMBSTONE_PREFIX, index)) !== -1) {
    const start = index + TOMBSTONE_PREFIX.length;
    let end = start;
    while (end - start < 64 && /[a-z0-9._-]/.test(source[end] ?? "")) end += 1;
    if (end > start && (allowTrailing || end < source.length)) {
      const provider = source.slice(start, end);
      onHit(provider);
    }
    index = start;
  }
}

async function scanAuthTombstones(path: string, onHit: (provider: string) => void): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const stream = createReadStream(path, { highWaterMark: AUTH_SCAN_CHUNK_BYTES });
    let carry = "";
    stream.on("data", (chunk: Buffer) => {
      const source = carry + chunk.toString("latin1");
      scanTombstones(source, onHit);
      carry = source.slice(-AUTH_SCAN_CARRY_BYTES);
    });
    stream.on("error", reject);
    stream.on("end", () => {
      scanTombstones(carry, onHit, true);
      resolve();
    });
  });
}

async function scanAuthSource(path: string, onHit: (provider: string) => void): Promise<void> {
  const content = process.env.OPENCODE_AUTH_CONTENT;
  if (content) {
    try {
      const value: unknown = JSON.parse(content);
    } catch {
      return scanAuthTombstones(path, onHit);
    }
    return;
  }
  return scanAuthTombstones(path, onHit);
}

function carriesTombstoneKey(entry: unknown, provider: string): boolean {
  if (!entry || typeof entry !== "object" || Array.isArray(entry)) return false;
  const candidate = entry as Record<string, unknown>;
  const value = sentinel(provider);
  return candidate.type === "api" && candidate.key === value ||
    candidate.type === "oauth" && (candidate.access === value || candidate.refresh === value);
}

// Effect's Config.boolean (effect@4.0.0-beta.74 dist/Config.js:541-562, the parser behind
// OpenCode's runtime-flags `bool()`) accepts exactly `true yes on 1 y` / `false no off 0 n`,
// case-sensitive. Only the DISABLING spellings and absence are treated as "custody may serve";
// anything else — an enabling spelling, a future spelling, or an unparseable value that may
// make OpenCode error — refuses custody. Fail closed: a guard that under-fires here sends the
// sentinel to the wire as the key.
const NATIVE_LLM_FALSE = new Set(["false", "no", "off", "0", "n"]);

export function nativeLlmEnabled(raw: string | undefined): boolean {
  if (raw === undefined) return false;
  return !NATIVE_LLM_FALSE.has(raw);
}

function logError(log: CustodyLogger, error: Error, provider: string) {
  log.error({
    provider,
    errorClass: error.name,
    errorCode: (error as NodeJS.ErrnoException).code,
    errorMessage: error.message,
  });
}

function authReadRefusal(error: unknown, fromBoundedScan = false): CustodyAuthReadError {
  const cause = error instanceof Error ? `${error.name}: ${error.message}` : String(error);
  return new CustodyAuthReadError(`auth-read failure: ${cause}${fromBoundedScan ? "; provider list came from a bounded tombstone scan" : ""}`);
}

export function createOpencodeClaustrumPlugin(dependencies: ConfigHookDependencies = {}): Plugin {
  const handleReader = dependencies.handleReader ?? readHandleFile;
  const authReader = dependencies.authReader ?? readAuthFile;
  const log = createLogger(dependencies.logSink ?? (dependencies.log ? serializedLogSink(dependencies.log) : undefined));
  if (process.env.CLAUSTRUM_CUSTODY_DISABLE === "1") {
    return async () => ({
      config: async () => {
        try {
          const owned = (await handleReader(defaultHandleFilePath())).providers
            .filter((provider) => provider.serve === OUR_PLUGIN_ID)
            .map((provider) => provider.provider);
          log.warn({
            errorCode: "custody_disabled",
            errorMessage: `Custody is deliberately off; any tombstoned provider WILL FAIL with a 401 while CLAUSTRUM_CUSTODY_DISABLE=1 sends the tombstone to the wire as the key. Real credentials return only via ck auth migrate-opencode --restore <provider> or unsetting the switch. Owned providers: ${owned.join(", ") || "none"}.`,
          });
        } catch {
          log.warn({
            errorCode: "custody_disabled",
            errorMessage: "Custody is deliberately off; any tombstoned provider WILL FAIL with a 401 while CLAUSTRUM_CUSTODY_DISABLE=1 sends the tombstone to the wire as the key. Real credentials return only via ck auth migrate-opencode --restore <provider> or unsetting the switch. Handle ownership was not read.",
          });
        }
      },
    });
  }
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
    if (connected) return connected;
    const pending = (async () => {
      const result = await detection();
      if (result.status !== "available") throw new Error(`Claustrum connection ${result.status}`);
      return clientFactory();
    })();
    connected = pending;
    try {
      return await pending;
    } catch (error) {
      if (connected === pending) connected = undefined;
      throw error;
    }
  }

  return async () => {
    let controllers: FreshnessController[] = [];
    return {
      config: async (input) => {
        for (const controller of controllers) controller.dispose();
        controllers = [];
        const cfg = input as MutableConfig;
        const providerConfig = cfg.provider ?? (cfg.provider = Object.create(null) as Record<string, ConfigProvider>);
        const configureRefusal = (provider: string, error: Error) => {
          // A raw scan can name a provider only in a note or a mis-keyed entry. Creating that
          // provider makes it visible to OpenCode, but preserves the required host-load superset;
          // cfg.provider is therefore the only hit storage: O(unique ids), like the host's own
          // provider entries. This is availability/UI direction only because the sentinel is non-secret.
          const configured = Object.hasOwn(providerConfig, provider)
            ? providerConfig[provider]!
            : (providerConfig[provider] = {});
          configured.options = {
            ...(configured.options ?? {}),
            fetch: async () => { throw error; },
          };
        };
        const configureAuthReadRefusals = async (error: unknown, ownedProviders: Iterable<string>) => {
          const refusal = authReadRefusal(error, true);
          const providers = new Set(ownedProviders);
          const refuse = (provider: string) => {
            if ((!SCANNED_PROVIDER_ID.test(provider) || FORBIDDEN_PROVIDER_IDS.has(provider)) && !Object.hasOwn(providerConfig, provider)) {
              logError(log, refusal, provider);
              return;
            }
            logError(log, refusal, provider);
            configureRefusal(provider, refusal);
          };
          try {
            await scanAuthSource(defaultAuthPath(), refuse);
          } catch (scanError) {
            logError(log, new CustodyAuthReadError(
              `bounded tombstone scan failed: ${scanError instanceof Error ? `${scanError.name}: ${scanError.message}` : String(scanError)}`,
            ), "auth-scan");
          }
          for (const provider of providers) refuse(provider);
        };
        let handles: OpenCodeHandleFileV1;
        try {
          handles = await handleReader(defaultHandleFilePath());
        } catch (error) {
          const typed = error instanceof HandleFileValidationError
            ? error
            : new HandleFileValidationError(error instanceof Error ? error.message : String(error));
          logError(log, typed, "handle-file");
          let auth: Record<string, unknown>;
          try {
            auth = await readAuth(defaultAuthPath(), authReader);
          } catch (authError) {
            await configureAuthReadRefusals(authError, []);
            return;
          }
          for (const [provider, entry] of Object.entries(auth)) {
            if (!carriesTombstoneKey(entry, provider)) continue;
            const refusal = new CustodyOrphanError(
              `handle file unavailable: ${typed.message}; tombstone ownership cannot be proven; run ck auth migrate-opencode`,
            );
            logError(log, refusal, provider);
            configureRefusal(provider, refusal);
          }
          return;
        }
        let auth: Record<string, unknown>;
        try {
          auth = await readAuth(defaultAuthPath(), authReader);
        } catch (error) {
          await configureAuthReadRefusals(
            error,
            handles.providers.filter((handle) => handle.serve === OUR_PLUGIN_ID).map((handle) => handle.provider),
          );
          return;
        }

        const byProvider = new Map(handles.providers.map((provider) => [provider.provider, provider]));
        const providers = [...byProvider.keys()];
        for (const provider of Object.keys(auth)) {
          if (!byProvider.has(provider) && carriesTombstoneKey(auth[provider], provider)) providers.push(provider);
        }

        for (const provider of providers) {
          const handle = byProvider.get(provider);
          const entry = Object.hasOwn(auth, provider) ? auth[provider] : undefined;
          const tombstone = isProviderTombstone(entry, provider);
          const consumesTombstone = carriesTombstoneKey(entry, provider);
          const owner = handle?.serve;

          if (!tombstone) {
            if (consumesTombstone) {
              const refusal = new CustodyOrphanError("tombstone key is not a canonical custody entry; refusing before OpenCode can load it");
              logError(log, refusal, provider);
              configureRefusal(provider, refusal);
              continue;
            }
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
            else {
              const refusal = new CustodyOrphanError("tombstone has no serving handle; run ck auth migrate-opencode");
              logError(log, refusal, provider);
              configureRefusal(provider, refusal);
            }
            continue;
          }

          // The native runtime reads `provider.options.apiKey` directly instead of this fetch
          // seam. Its case-sensitive flag parser therefore gets an allowlist, not a best guess.
          if (nativeLlmEnabled(process.env.OPENCODE_EXPERIMENTAL_NATIVE_LLM)) {
            const observed = process.env.OPENCODE_EXPERIMENTAL_NATIVE_LLM;
            const refusal = new CustodyNativeRuntimeError(
              `OpenCode native LLM mode bypasses the custody fetch seam; OPENCODE_EXPERIMENTAL_NATIVE_LLM=${observed} must be unset or disabled`,
            );
            logError(log, refusal, provider);
            configureRefusal(provider, refusal);
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
              verifyOwnership: async () => {
                let current: OpenCodeHandleFileV1;
                try {
                  current = await handleReader(defaultHandleFilePath());
                } catch (error) {
                  throw new CustodyOwnershipError(
                    `could not verify custody handle ownership: ${error instanceof Error ? error.message : String(error)}`,
                  );
                }
                if (current.providers.find((candidate) => candidate.provider === provider)?.serve !== OUR_PLUGIN_ID) {
                  throw new CustodyOwnershipError(
                    `custody handle ownership changed for provider=${provider}; reload OpenCode after ck auth migrate-opencode`,
                  );
                }
              },
              readAuthEntry: async () => (await readAuth(defaultAuthPath(), authReader))[provider],
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
