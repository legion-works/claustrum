export const TOMBSTONE_PREFIX = "claustrum-tombstone:v1:";

export type OpenCodeApiEntry = { type: "api"; key: string };
export type OpenCodeOauthEntry = {
  type: "oauth";
  refresh: string;
  access: string;
  expires: number;
};
export type OpenCodeAuthEntry = OpenCodeApiEntry | OpenCodeOauthEntry;

export function sentinel(provider: string): string {
  return `${TOMBSTONE_PREFIX}${provider}`;
}

export function tombstoneFor(shape: "api" | "oauth", provider: string): OpenCodeAuthEntry {
  const value = sentinel(provider);
  if (shape === "api") return { type: "api", key: value };
  return { type: "oauth", refresh: value, access: value, expires: 0 };
}

export function isProviderTombstone(entry: unknown, provider: string): boolean {
  if (!entry || typeof entry !== "object") return false;
  const candidate = entry as Record<string, unknown>;
  const value = sentinel(provider);
  if (candidate.type === "api") {
    return Object.keys(candidate).length === 2 && candidate.key === value;
  }
  return candidate.type === "oauth" && Object.keys(candidate).length === 4 &&
    candidate.refresh === value && candidate.access === value && candidate.expires === 0;
}
