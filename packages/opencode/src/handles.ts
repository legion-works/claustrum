export const OUR_PLUGIN_ID = "opencode-claustrum";

export type HandleAccount = { label: string; handle: string; credential_id: string };
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
    typeof account.credential_id === "string";
}

export function parseHandleFile(value: unknown): OpenCodeHandleFileV1 {
  if (!value || typeof value !== "object") throw new Error("handle file must be an object");
  const file = value as Record<string, unknown>;
  if (file.version !== 1 || !Array.isArray(file.providers)) {
    throw new Error("handle file must have version 1 and providers");
  }
  const providers = file.providers.map((provider, index): HandleProvider => {
    if (!provider || typeof provider !== "object") throw new Error(`provider ${index} must be an object`);
    const item = provider as Record<string, unknown>;
    if (typeof item.provider !== "string" || !item.provider) throw new Error(`provider ${index} has invalid provider`);
    if (item.shape !== "api" && item.shape !== "oauth") throw new Error(`provider ${index} has invalid shape`);
    if (typeof item.serve !== "string" || !item.serve) throw new Error(`provider ${index} requires serve`);
    if (!Array.isArray(item.accounts) || !item.accounts.every(isAccount)) {
      throw new Error(`provider ${index} has invalid accounts`);
    }
    return {
      provider: item.provider,
      shape: item.shape,
      serve: item.serve,
      accounts: item.accounts,
    };
  });
  return { version: 1, providers };
}
