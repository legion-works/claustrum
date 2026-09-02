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

function isStringRecord(value: unknown): value is Record<string, string> {
  return !!value && typeof value === "object" && !Array.isArray(value) &&
    Object.values(value as Record<string, unknown>).every((item) => typeof item === "string");
}

export function decodeHostAuthEntry(entry: unknown): Record<string, unknown> | undefined {
  if (!entry || typeof entry !== "object" || Array.isArray(entry)) return undefined;
  const candidate = entry as Record<string, unknown>;
  if (candidate.type === "api") {
    if (typeof candidate.key !== "string" || candidate.metadata !== undefined && !isStringRecord(candidate.metadata)) return undefined;
    return candidate.metadata === undefined
      ? { type: "api", key: candidate.key }
      : { type: "api", key: candidate.key, metadata: candidate.metadata };
  }
  if (candidate.type === "wellknown") {
    return typeof candidate.key === "string" && typeof candidate.token === "string"
      ? { type: "wellknown", key: candidate.key, token: candidate.token }
      : undefined;
  }
  if (candidate.type !== "oauth" || typeof candidate.refresh !== "string" || typeof candidate.access !== "string" || typeof candidate.expires !== "number" ||
    candidate.accountId !== undefined && typeof candidate.accountId !== "string" ||
    candidate.enterpriseUrl !== undefined && typeof candidate.enterpriseUrl !== "string") return undefined;
  return {
    type: "oauth",
    refresh: candidate.refresh,
    access: candidate.access,
    expires: candidate.expires,
    ...(candidate.accountId === undefined ? {} : { accountId: candidate.accountId }),
    ...(candidate.enterpriseUrl === undefined ? {} : { enterpriseUrl: candidate.enterpriseUrl }),
  };
}

function hasSentinel(value: unknown): boolean {
  return typeof value === "string" && value.startsWith(TOMBSTONE_PREFIX);
}

export function carriesSentinel(entry: unknown): boolean {
  if (!entry || typeof entry !== "object" || Array.isArray(entry)) return false;
  const candidate = entry as Record<string, unknown>;
  // Disk entries are decoded and stripped before this point; env entries are raw. Walk only fields
  // the host reads at fixed depth, not arbitrary JSON: excess disk fields cannot reach the wire and
  // recursive env traversal would make untrusted nesting a config-hook stack hazard. WellKnown is
  // excluded because config substitution never enters provider.ts model requests, and treating its
  // URL key as a provider would mint bogus config.
  if (candidate.type === "api" && typeof candidate.key === "string") {
    return hasSentinel(candidate.key) || !!candidate.metadata && typeof candidate.metadata === "object" &&
      !Array.isArray(candidate.metadata) && Object.values(candidate.metadata).some(hasSentinel);
  }
  return candidate.type === "oauth" && typeof candidate.refresh === "string" && typeof candidate.access === "string" &&
    typeof candidate.expires === "number" &&
    (hasSentinel(candidate.access) || hasSentinel(candidate.refresh) || hasSentinel(candidate.accountId) || hasSentinel(candidate.enterpriseUrl));
}

export function sentinelShapeDrift(entry: unknown, provider: string): string {
  const candidate = entry as Record<string, unknown>;
  if (candidate.type === "api") {
    const extra = Object.keys(candidate).filter((key) => key !== "type" && key !== "key");
    return extra.length
      ? `tombstone_shape_drift: api entry has extra keys: ${extra.join(", ")}`
      : `tombstone_shape_drift: api key binds a provider other than ${provider}`;
  }
  const extra = Object.keys(candidate).filter((key) => !["type", "refresh", "access", "expires"].includes(key));
  return extra.length
    ? `tombstone_shape_drift: oauth entry has extra keys: ${extra.join(", ")}`
    : "tombstone_shape_drift: oauth access and refresh do not form the canonical pair";
}
