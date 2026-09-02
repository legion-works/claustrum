import { createHash } from 'node:crypto'
import { realpathSync } from 'node:fs'
import { resolve } from 'node:path'
import type { BindIdentity } from '@cortexkit/subc-client'

export function storageFingerprint(storagePath: string): string {
  const absolutePath = resolve(storagePath)
  let canonicalPath: string
  try {
    canonicalPath = realpathSync(absolutePath)
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error
    canonicalPath = absolutePath
  }
  return createHash('sha256').update(canonicalPath).digest('hex').slice(0, 12)
}

export function storeIdentity(projectRoot: string, storagePath: string): BindIdentity {
  return {
    project_root: projectRoot,
    harness: 'opencode',
    session: `store-${storageFingerprint(storagePath)}`,
  }
}
