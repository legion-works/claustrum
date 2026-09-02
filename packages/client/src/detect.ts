import { statSync } from 'node:fs'
import { tmpdir, userInfo } from 'node:os'
import { join } from 'node:path'
import { PROTOCOL_VERSION, readConnectionFile } from '@cortexkit/subc-client'

export type ClaustrumEndpoint = {
  host: string
  port: number
}

export type ClaustrumDetection =
  | { status: 'available'; schema: number; wireVersion: number; endpoints: ClaustrumEndpoint[] }
  | { status: 'absent'; path: string }
  | { status: 'malformed'; path: string; reason: string }

export function getDefaultClaustrumConnectionPath(): string {
  const uid = process.getuid?.() ?? userInfo().uid
  const runtime = process.env.XDG_RUNTIME_DIR?.trim()
  const candidates = [
    ...(runtime ? [join(runtime, 'subc-connection.json')] : []),
    join(userInfo().homedir, '.local', 'share', 'cortexkit', 'run', 'subc-connection.json'),
    join(tmpdir(), `subc-${uid}.connection.json`),
  ]
  // Keep the client aligned with `ck`: runtime, production data home, then temp fallback.
  return candidates.find((candidate) => {
    try { return statSync(candidate).isFile() } catch { return false }
  }) ?? candidates[0]!
}

export function resolveClaustrumConnectionPath(explicit?: string): string {
  return explicit?.trim() || process.env.CLAUSTRUM_SUBC_CONNECTION?.trim() || getDefaultClaustrumConnectionPath()
}

export async function detectClaustrumConnection(
  explicitPath?: string,
): Promise<ClaustrumDetection> {
  const path = resolveClaustrumConnectionPath(explicitPath)
  let value: Awaited<ReturnType<typeof readConnectionFile>>
  try {
    value = await readConnectionFile(path)
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return { status: 'absent', path }
    }
    return {
      status: 'malformed',
      path,
      reason: 'connection file could not be read or validated',
    }
  }

  return {
    status: 'available',
    schema: value.schema,
    wireVersion: PROTOCOL_VERSION,
    endpoints: value.endpoints,
  }
}
