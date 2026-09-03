import { afterEach, describe, expect, test } from 'bun:test'
import { chmod, lstat, mkdir, mkdtemp, readFile, readdir, rename, rm, stat, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { basename, join } from 'node:path'

import {
  __setManifestLockTestOptions,
  MANIFEST_LOCK,
  withManifestLock,
  writeHandleFileLocked,
} from '../manifest-lock'

const roots: string[] = []
const handle = (letter: string) => `ckh_${letter.repeat(43)}`

async function manifestPath(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'claustrum-manifest-lock-'))
  roots.push(root)
  return join(root, 'opencode-handles.json')
}

function provider(provider: string, tenant: string) {
  return {
    provider,
    shape: 'api' as const,
    serve: tenant,
    accounts: [{
      label: 'main',
      handle: handle(provider[0] ?? 'A'),
      credential_id: `apikey:${provider}:main`,
    }],
  }
}

async function owner(path: string, claimedAtMs: number, tenant = 'other-tenant'): Promise<void> {
  const lockPath = `${path}.lock`
  await mkdir(lockPath, { mode: 0o700 })
  await writeFile(join(lockPath, 'owner'), `${JSON.stringify({
    tenant,
    pid: 41,
    claimed_at_ms: claimedAtMs,
    nonce: '0123456789abcdef0123456789abcdef',
  })}\n`, { mode: 0o600 })
  await chmod(join(lockPath, 'owner'), 0o600)
}

afterEach(async () => {
  __setManifestLockTestOptions()
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })))
})

describe('manifest writer lock', () => {
  test('two concurrent tenant writers preserve both provider blocks', async () => {
    const path = await manifestPath()
    const firstEntered = Promise.withResolvers<void>()
    const releaseFirst = Promise.withResolvers<void>()

    const first = writeHandleFileLocked(path, 'anthropic-auth', async (file) => {
      firstEntered.resolve()
      await releaseFirst.promise
      file.providers.push(provider('anthropic', 'anthropic-auth'))
    })
    await firstEntered.promise
    const second = writeHandleFileLocked(path, 'openai-auth', (file) => {
      file.providers.push(provider('openai', 'openai-auth'))
    })
    releaseFirst.resolve()
    await Promise.all([first, second])

    const written = JSON.parse(await readFile(path, 'utf8')) as { providers: Array<{ provider: string }> }
    expect(written.providers.map((entry) => entry.provider).sort()).toEqual(['anthropic', 'openai'])
  })

  test('stale owner is evicted by rename and retained as a quarantine directory', async () => {
    const path = await manifestPath()
    await owner(path, Date.now() - MANIFEST_LOCK.ttlMs - 1)

    await withManifestLock(path, 'anthropic-auth', async () => {})

    const suffixes = (await readdir(join(path, '..')))
      .filter((name) => name.startsWith(`${basename(path)}.lock.stale-`))
      .map((name) => name.slice(basename(path).length))
    expect(suffixes).toHaveLength(1)
    expect(MANIFEST_LOCK.staleTargetRe.test(suffixes[0]!)).toBe(true)
  })

  test('fresh owner fails loudly after the bounded retry window', async () => {
    const path = await manifestPath()
    __setManifestLockTestOptions({ ttlMs: 40, renewEveryMs: 10, retryMinMs: 2, retryMaxMs: 3 })
    await owner(path, Date.now())

    const started = Date.now()
    await expect(withManifestLock(path, 'anthropic-auth', async () => {})).rejects.toThrow('manifest lock busy')
    expect(Date.now() - started).toBeGreaterThanOrEqual(35)
  })

  test('owner file exists while held and disappears with the lock after release', async () => {
    const path = await manifestPath()
    const lockPath = `${path}.lock`

    await withManifestLock(path, 'anthropic-auth', async () => {
      const parsed = JSON.parse(await readFile(join(lockPath, 'owner'), 'utf8')) as Record<string, unknown>
      expect(Object.keys(parsed).sort()).toEqual([...MANIFEST_LOCK.ownerKeys].sort())
      expect(parsed.tenant).toBe('anthropic-auth')
    })

    await expect(stat(lockPath)).rejects.toMatchObject({ code: 'ENOENT' })
  })

  test('two stale evictors produce one eviction winner and never overlap holders', async () => {
    const path = await manifestPath()
    await owner(path, Date.now() - MANIFEST_LOCK.ttlMs - 1)
    let waiting = 0
    const bothReady = Promise.withResolvers<void>()
    let evictionWins = 0
    __setManifestLockTestOptions({
      beforeEvict: async () => {
        waiting += 1
        if (waiting === 2) bothReady.resolve()
        await bothReady.promise
      },
      afterEvict: () => { evictionWins += 1 },
      retryMinMs: 2,
      retryMaxMs: 3,
    })
    let active = 0
    let maxActive = 0
    const hold = async () => {
      active += 1
      maxActive = Math.max(maxActive, active)
      await Bun.sleep(15)
      active -= 1
    }

    await Promise.all([
      withManifestLock(path, 'anthropic-auth', hold),
      withManifestLock(path, 'openai-auth', hold),
    ])

    expect(evictionWins).toBe(1)
    expect(maxActive).toBe(1)
  })

  test('an expired holder does not release its directory and logs the lost lease', async () => {
    const path = await manifestPath()
    const lockPath = `${path}.lock`
    __setManifestLockTestOptions({ ttlMs: 40, renewEveryMs: 1_000, retryMinMs: 2, retryMaxMs: 3 })
    const warnings: unknown[][] = []
    const originalWarn = console.warn
    console.warn = (...args: unknown[]) => { warnings.push(args) }
    try {
      await withManifestLock(path, 'anthropic-auth', async () => {
        const ownerPath = join(lockPath, 'owner')
        const parsed = JSON.parse(await readFile(ownerPath, 'utf8')) as Record<string, unknown>
        parsed.claimed_at_ms = Date.now() - 41
        await writeFile(ownerPath, `${JSON.stringify(parsed)}\n`, { mode: 0o600 })
      })
    } finally {
      console.warn = originalWarn
    }

    await expect(stat(lockPath)).resolves.toBeDefined()
    expect(warnings.some((args) => args.includes('manifest lock lease lost, not releasing'))).toBe(true)
  })

  test('atomic publication remains 0600 under umask 022', async () => {
    const path = await manifestPath()
    const previous = process.umask(0o022)
    try {
      await writeHandleFileLocked(path, 'anthropic-auth', (file) => {
        file.providers.push(provider('anthropic', 'anthropic-auth'))
      })
    } finally {
      process.umask(previous)
    }
    expect((await stat(path)).mode & 0o777).toBe(0o600)
  })

  test('creates a missing manifest parent before claiming its colocated lock', async () => {
    const root = await mkdtemp(join(tmpdir(), 'claustrum-manifest-parent-'))
    roots.push(root)
    const path = join(root, 'nested', 'opencode-handles.json')

    await writeHandleFileLocked(path, 'anthropic-auth', (file) => {
      file.providers.push(provider('anthropic', 'anthropic-auth'))
    })

    expect((await stat(path)).mode & 0o777).toBe(0o600)
  })

  test('pins the shared lock constants and renewal bound', () => {
    expect(MANIFEST_LOCK.ttlMs).toBe(30_000)
    expect(MANIFEST_LOCK.renewEveryMs).toBe(10_000)
    expect(MANIFEST_LOCK.ownerKeys).toEqual(['tenant', 'pid', 'claimed_at_ms', 'nonce'])
    expect(MANIFEST_LOCK.staleTargetRe.source).toBe('^\\.lock\\.stale-\\d+-[A-Za-z0-9_-]+$')
    expect(MANIFEST_LOCK.renewEveryMs * 3).toBeLessThanOrEqual(MANIFEST_LOCK.ttlMs)
  })

  test('reads a Rust-shaped owner fixture using the shared field contract', async () => {
    const path = await manifestPath()
    __setManifestLockTestOptions({ ttlMs: 30, renewEveryMs: 10, retryMinMs: 2, retryMaxMs: 3 })
    await owner(path, Date.now(), 'opencode-claustrum')
    await expect(withManifestLock(path, 'anthropic-auth', async () => {})).rejects.toThrow('manifest lock busy')
  })

  test('refuses a dangling manifest symlink without replacing it', async () => {
    const path = await manifestPath()
    const target = join(path, '..', 'missing-target.json')
    await symlink(target, path)

    await expect(writeHandleFileLocked(path, 'anthropic-auth', (file) => {
      file.providers.push(provider('anthropic', 'anthropic-auth'))
    })).rejects.toThrow('handle file must be a regular file')

    expect((await lstat(path)).isSymbolicLink()).toBe(true)
    await expect(stat(target)).rejects.toMatchObject({ code: 'ENOENT' })
  })

  test('aborts before manifest rename when renewal loses the original lock path', async () => {
    const path = await manifestPath()
    await writeHandleFileLocked(path, 'anthropic-auth', (file) => {
      file.providers.push(provider('anthropic', 'anthropic-auth'))
    })
    const before = await readFile(path, 'utf8')
    __setManifestLockTestOptions({
      ttlMs: 100,
      renewEveryMs: 2,
      retryMinMs: 2,
      retryMaxMs: 3,
      beforeManifestRename: async (lockPath: string) => {
        await rename(lockPath, `${lockPath}.vanished`)
        await Bun.sleep(10)
      },
    } as never)

    await expect(writeHandleFileLocked(path, 'anthropic-auth', (file) => {
      file.providers[0]!.accounts.push({
        label: 'backup',
        handle: handle('Z'),
        credential_id: 'apikey:anthropic:backup',
      })
    })).rejects.toThrow('manifest lock renewal failed; write aborted')

    expect(await readFile(path, 'utf8')).toBe(before)
  })

  test('pins missing and unparseable owner records as busy without eviction', async () => {
    const path = await manifestPath()
    const lockPath = `${path}.lock`
    __setManifestLockTestOptions({ ttlMs: 25, renewEveryMs: 8, retryMinMs: 2, retryMaxMs: 3 })
    for (const ownerSource of [undefined, '{']) {
      await mkdir(lockPath, { mode: 0o700 })
      if (ownerSource !== undefined) {
        await writeFile(join(lockPath, 'owner'), ownerSource, { mode: 0o600 })
      }

      await expect(withManifestLock(path, 'anthropic-auth', async () => {})).rejects.toThrow('manifest lock busy')
      expect((await lstat(lockPath)).isDirectory()).toBe(true)
      expect((await readdir(join(path, '..'))).some((name) => name.includes('.lock.stale-'))).toBe(false)
      await rm(lockPath, { recursive: true })
    }
  })
})
