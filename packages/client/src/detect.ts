import { existsSync } from 'node:fs'
import { readFile } from 'node:fs/promises'
import { tmpdir, userInfo } from 'node:os'
import { join } from 'node:path'

export type ClaustrumEndpoint = {
  host: string
  port: number
}

export type ClaustrumDetection =
  | { status: 'available'; schema: number; wireVersion: number; endpoints: ClaustrumEndpoint[] }
  | { status: 'absent'; path: string }
  | { status: 'malformed'; path: string; reason: string }

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function isEndpoint(value: unknown): value is ClaustrumEndpoint {
  return (
    isRecord(value) &&
    typeof value.host === 'string' &&
    value.host.length > 0 &&
    typeof value.port === 'number' &&
    Number.isInteger(value.port) &&
    value.port > 0 &&
    value.port <= 65_535
  )
}

export function getDefaultClaustrumConnectionPath(): string {
  const uid = process.getuid?.() ?? userInfo().uid
  const runtime = process.env.XDG_RUNTIME_DIR?.trim()
  const candidates = [
    ...(runtime ? [join(runtime, 'subc-connection.json')] : []),
    join(userInfo().homedir, '.local', 'share', 'cortexkit', 'run', 'subc-connection.json'),
    join(tmpdir(), `subc-${uid}.connection.json`),
  ]
  // Keep the client aligned with `ck`: runtime, production data home, then temp fallback.
  return candidates.find(existsSync) ?? candidates[0] ?? `/run/user/${uid}/subc-connection.json`
}

export function resolveClaustrumConnectionPath(explicit?: string): string {
  return explicit?.trim() || process.env.CLAUSTRUM_SUBC_CONNECTION?.trim() || getDefaultClaustrumConnectionPath()
}

export async function detectClaustrumConnection(
  explicitPath?: string,
): Promise<ClaustrumDetection> {
  const path = resolveClaustrumConnectionPath(explicitPath)
  let value: unknown
  try {
    value = JSON.parse(await readFile(path, 'utf8'))
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return { status: 'absent', path }
    }
    return {
      status: 'malformed',
      path,
      reason: error instanceof Error ? error.message : String(error),
    }
  }

  if (
    !isRecord(value) ||
    typeof value.schema !== 'number' ||
    !Number.isSafeInteger(value.schema) || value.schema < 0 ||
    typeof value.wire_version !== 'number' ||
    !Number.isSafeInteger(value.wire_version) || value.wire_version < 0 ||
    !Array.isArray(value.endpoints) ||
    value.endpoints.length === 0 ||
    !value.endpoints.every(isEndpoint)
  ) {
    return {
      status: 'malformed',
      path,
      reason: 'connection file has an invalid schema, wire_version, or endpoints',
    }
  }

  return {
    status: 'available',
    schema: value.schema,
    wireVersion: value.wire_version,
    endpoints: value.endpoints,
  }
}
