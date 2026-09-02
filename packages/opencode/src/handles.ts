import { readFile, stat as nodeStat } from "node:fs/promises";
import { userInfo } from "node:os";
import { join } from "node:path";

import { HandleFileValidationError } from "./errors";

export const OUR_PLUGIN_ID = "opencode-claustrum";

export type HandleAccount = {
  label: string;
  handle: string;
  credential_id: string;
  superseded?: string[];
};
export type HandleProvider = {
  provider: string;
  shape: "api" | "oauth";
  serve: string;
  accounts: HandleAccount[];
};
export type OpenCodeHandleFileV1 = { version: 1; providers: HandleProvider[] };

function isAccount(value: unknown): value is HandleAccount {
  if (!value || typeof value !== "object") return false;
  const account = value as Record<string, unknown>;
  return typeof account.label === "string" && typeof account.handle === "string" &&
    typeof account.credential_id === "string" &&
    (account.superseded === undefined ||
      (Array.isArray(account.superseded) && account.superseded.every((handle) => typeof handle === "string")));
}

function handleIsValid(handle: unknown): handle is string {
  return typeof handle === "string" && handle.startsWith("ckh_") && handle.length === 47;
}

function invalid(message: string): never {
  throw new HandleFileValidationError(message);
}

export function parseHandleFile(value: unknown): OpenCodeHandleFileV1 {
  if (!value || typeof value !== "object") invalid("handle file must be an object");
  const file = value as Record<string, unknown>;
  if (file.version !== 1 || !Array.isArray(file.providers)) {
    invalid("handle file must have version 1 and providers");
  }
  const providerIds = new Set<string>();
  const providers = file.providers.map((provider, index): HandleProvider => {
    if (!provider || typeof provider !== "object") invalid(`provider ${index} must be an object`);
    const item = provider as Record<string, unknown>;
    if (typeof item.provider !== "string" || !item.provider) invalid(`provider ${index} has invalid provider`);
    if (providerIds.has(item.provider)) invalid(`provider ${index} duplicates provider ${item.provider}`);
    providerIds.add(item.provider);
    if (item.shape !== "api" && item.shape !== "oauth") invalid(`provider ${index} has invalid shape`);
    if (typeof item.serve !== "string" || !item.serve) invalid(`provider ${index} requires serve`);
    if (!Array.isArray(item.accounts) || !item.accounts.every(isAccount)) {
      invalid(`provider ${index} has invalid accounts`);
    }
    const labels = new Set<string>();
    for (const account of item.accounts) {
      if (!account.label) invalid(`provider ${index} has an empty account label`);
      if (labels.has(account.label)) invalid(`provider ${index} duplicates account label ${account.label}`);
      labels.add(account.label);
      if (!handleIsValid(account.handle)) invalid(`provider ${index} account ${account.label} has invalid handle`);
      if (!account.credential_id) invalid(`provider ${index} account ${account.label} has invalid credential id`);
      if (account.superseded?.some((handle) => !handleIsValid(handle))) {
        invalid(`provider ${index} account ${account.label} has invalid superseded handle`);
      }
    }
    return {
      provider: item.provider,
      shape: item.shape,
      serve: item.serve,
      accounts: item.accounts.map((account) => ({
        ...account,
        ...(account.superseded === undefined ? {} : { superseded: account.superseded }),
      })),
    };
  });
  return { version: 1, providers };
}

type HandleFileStat = { isFile(): boolean; mode: number; uid?: number };
export type HandleFileIo = {
  stat?: (path: string) => Promise<HandleFileStat>;
  readFile?: (path: string, encoding: "utf8") => Promise<string>;
  currentUid?: () => number | undefined;
};

export function defaultHandleFilePath(env: NodeJS.ProcessEnv = process.env): string {
  if (env.CLAUSTRUM_OPENCODE_HANDLES) return env.CLAUSTRUM_OPENCODE_HANDLES;
  const configHome = env.XDG_CONFIG_HOME || (env.HOME ? join(env.HOME, ".config") : ".config");
  return join(configHome, "cortexkit", "opencode-handles.json");
}

function currentUid(): number | undefined {
  return process.getuid?.() ?? userInfo().uid;
}

export async function readHandleFile(path = defaultHandleFilePath(), io: HandleFileIo = {}): Promise<OpenCodeHandleFileV1> {
  const stat = io.stat ?? nodeStat;
  const read = io.readFile ?? readFile;
  let metadata: HandleFileStat;
  try {
    metadata = await stat(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return { version: 1, providers: [] };
    invalid(`cannot stat handle file: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (!metadata.isFile()) invalid("handle file must be a regular file");
  if ((metadata.mode & 0o777) !== 0o600) invalid("handle file mode must be exactly 0600");
  const uid = io.currentUid ?? currentUid;
  const expectedUid = uid();
  if (expectedUid !== undefined && metadata.uid !== undefined && metadata.uid !== expectedUid) {
    invalid("handle file is not owned by the current uid");
  }
  let source: string;
  try {
    source = await read(path, "utf8");
  } catch (error) {
    invalid(`cannot read handle file: ${error instanceof Error ? error.message : String(error)}`);
  }
  try {
    return parseHandleFile(JSON.parse(source));
  } catch (error) {
    if (error instanceof HandleFileValidationError) throw error;
    invalid(`handle file contains invalid JSON: ${error instanceof Error ? error.message : String(error)}`);
  }
}
