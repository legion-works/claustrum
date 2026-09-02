import { constants } from "node:fs";
import { lstat as nodeLstat, open as nodeOpen, readFile, stat as nodeStat } from "node:fs/promises";
import { userInfo } from "node:os";
import { dirname, join } from "node:path";
import { createHash } from "node:crypto";

import { boundedBytesText, readBounded, type BoundedReadDescriptor } from "./bounded-read";
import { HandleFileValidationError } from "./errors";
import { parseSecretJson, SecretJsonParseError } from "./secret-json";

export const OUR_PLUGIN_ID = "opencode-claustrum";
const HANDLE_FILE_MAX_BYTES = 256 * 1024;
const PROVIDER_ID = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const FORBIDDEN_IDENTIFIERS = new Set(["__proto__", "constructor", "prototype"]);

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
  return typeof handle === "string" && /^ckh_[A-Za-z0-9_-]{43}$/.test(handle);
}

function identifierIsValid(value: unknown): value is string {
  return typeof value === "string" && PROVIDER_ID.test(value) && !FORBIDDEN_IDENTIFIERS.has(value);
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
    if (!identifierIsValid(item.provider)) invalid(`provider ${index} has invalid provider`);
    if (providerIds.has(item.provider)) invalid(`provider ${index} duplicates provider ${item.provider}`);
    providerIds.add(item.provider);
    if (item.shape !== "api" && item.shape !== "oauth") invalid(`provider ${index} has invalid shape`);
    if (typeof item.serve !== "string" || !item.serve) invalid(`provider ${index} requires serve`);
    if (!Array.isArray(item.accounts) || item.accounts.length === 0 || !item.accounts.every(isAccount)) {
      invalid(`provider ${index} has invalid accounts`);
    }
    const labels = new Set<string>();
    for (const account of item.accounts) {
      if (!identifierIsValid(account.label)) invalid(`provider ${index} has an invalid account label`);
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

type HandleFileStat = {
  isFile(): boolean;
  isDirectory?(): boolean;
  isSymbolicLink?(): boolean;
  mode: number;
  size?: number;
  uid?: number;
  mtimeMs?: number;
};
type HandleFileDescriptor = BoundedReadDescriptor & {
  stat(): Promise<HandleFileStat>;
  readFile(options: { encoding: "utf8" }): Promise<string>;
  close(): Promise<void>;
};
export type HandleFileIo = {
  stat?: (path: string) => Promise<HandleFileStat>;
  lstat?: (path: string) => Promise<HandleFileStat>;
  readFile?: (path: string, encoding: "utf8") => Promise<string>;
  // Injectable descriptor: when supplied, the handle reader uses a bounded read into a
  // cap+1 buffer instead of `readFile()`. The cap check then catches a TOCTOU write that
  // grows the file between fstat and read; the unbounded path is preserved for callers
  // that pre-trust the source. Mirrors `ConfigHookDependencies.authReader`'s `openFile`
  // so a grow-after-fstat handle test can exercise the same bounded read path.
  open?: (path: string) => Promise<HandleFileDescriptor>;
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

type HandleFileSnapshot = {
  file: OpenCodeHandleFileV1;
  source?: string;
  mtimeMs?: number;
};

async function readHandleSnapshot(path = defaultHandleFilePath(), io: HandleFileIo = {}): Promise<HandleFileSnapshot> {
  const stat = io.stat ?? nodeStat;
  const lstat = io.lstat ?? nodeLstat;
  const read = io.readFile ?? readFile;
  const openFd = io.open ?? ((candidate: string) => nodeOpen(candidate, constants.O_RDONLY | constants.O_NOFOLLOW));
  let descriptor: HandleFileDescriptor | undefined;
  try {
    let metadata: HandleFileStat;
    try {
      if (io.lstat || io.readFile) {
        metadata = await lstat(path);
      } else {
        descriptor = await openFd(path);
        metadata = await descriptor.stat();
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return { file: { version: 1, providers: [] } };
      if ((error as NodeJS.ErrnoException).code === "ELOOP") invalid("handle file must not be a symlink");
      invalid(`cannot stat handle file: ${error instanceof Error ? error.message : String(error)}`);
    }
    if (metadata.isSymbolicLink?.()) invalid("handle file must not be a symlink");
    if (!metadata.isFile()) invalid("handle file must be a regular file");
    if ((metadata.size ?? 0) > HANDLE_FILE_MAX_BYTES) invalid("handle file exceeds 256 KiB");
    if ((metadata.mode & 0o777) !== 0o600) invalid("handle file mode must be exactly 0600");
    const uid = io.currentUid ?? currentUid;
    const expectedUid = uid();
    if (expectedUid !== undefined && metadata.uid !== undefined && metadata.uid !== expectedUid) {
      invalid("handle file is not owned by the current uid");
    }
    let parent: HandleFileStat;
    try {
      parent = await stat(dirname(path));
    } catch (error) {
      invalid(`cannot stat handle file parent: ${error instanceof Error ? error.message : String(error)}`);
    }
    if (!parent.isDirectory?.()) invalid("handle file parent must be a directory");
    if (expectedUid !== undefined && parent.uid !== undefined && parent.uid !== expectedUid) {
      invalid("handle file parent is not owned by the current uid");
    }
    if ((parent.mode & 0o002) !== 0 && (parent.mode & 0o1000) === 0) {
      invalid("handle file parent is world-writable without sticky bit");
    }
    let source: string;
    try {
      if (descriptor) {
        // Bounded read on the already-fstat'd descriptor closes the TOCTOU window a
        // size-only check leaves open: a writer that grows the file between fstat and
        // readFile would otherwise drive the read past the cap. The shared helper
        // allocates the cap+1 buffer and reports bytes > cap so the message is uniform
        // across auth and handle paths.
        const { buffer, bytes } = await readBounded(descriptor, HANDLE_FILE_MAX_BYTES);
        if (bytes === -1) invalid("handle file exceeds 256 KiB");
        source = boundedBytesText(bytes, buffer);
      } else {
        source = await read(path, "utf8");
      }
    } catch (error) {
      if (error instanceof HandleFileValidationError) throw error;
      invalid(`cannot read handle file: ${error instanceof Error ? error.message : String(error)}`);
    }
    let value: unknown;
    try {
      value = parseSecretJson(source, "handle file");
    } catch (error) {
      if (error instanceof SecretJsonParseError) invalid("handle file contains invalid JSON");
      throw error;
    }
    return {
      file: parseHandleFile(value),
      source,
      mtimeMs: metadata.mtimeMs,
    };
  } finally {
    await descriptor?.close();
  }
}

export async function readHandleFile(path = defaultHandleFilePath(), io: HandleFileIo = {}): Promise<OpenCodeHandleFileV1> {
  return (await readHandleSnapshot(path, io)).file;
}

export async function handleFileRevision(path = defaultHandleFilePath(), io: HandleFileIo = {}): Promise<string> {
  const snapshot = await readHandleSnapshot(path, io);
  if (snapshot.source === undefined) invalid("cannot revise absent handle file");
  return `${snapshot.mtimeMs ?? 0}:${createHash("sha256").update(snapshot.source).digest("hex")}`;
}
