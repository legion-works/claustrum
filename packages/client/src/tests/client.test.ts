import { afterEach, describe, expect, test } from 'bun:test'
import { createHash } from 'node:crypto'
import { chmod, mkdir, mkdtemp, realpath, rm, symlink, writeFile } from 'node:fs/promises'
import { createServer } from 'node:net'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { PROTOCOL_VERSION, SubcCallError } from '@cortexkit/subc-client'
import {
  ClaustrumClient,
  detectClaustrumConnection,
  getDefaultClaustrumConnectionPath,
} from '../index'

type Call = {
  moduleId: string
  method: string
  params: unknown
  options: Record<string, unknown>
}

class FakeDaemon {
  readonly calls: Call[] = []
  closed = false

  constructor(
    readonly responses: unknown[] = [],
    readonly failure?: Error,
  ) {}

  async call(
    moduleId: string,
    method: string,
    params: unknown,
    options: Record<string, unknown>,
  ): Promise<unknown> {
    this.calls.push({ moduleId, method, params, options })
    if (this.failure) throw this.failure
    return this.responses.shift() ?? { result: {} }
  }

  close(): void {
    this.closed = true
  }
}

const tempDirs: string[] = []
const originalConnection = process.env.CLAUSTRUM_SUBC_CONNECTION
const originalModuleId = process.env.SUBC_MODULE_ID
const originalLaunchNonce = process.env.SUBC_LAUNCH_NONCE
const originalXdgRuntime = process.env.XDG_RUNTIME_DIR
const originalHome = process.env.HOME
const originalTmpdir = process.env.TMPDIR

async function tempPath(name: string): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'claustrum-client-'))
  tempDirs.push(dir)
  return join(dir, name)
}

function terminal(code: string): SubcCallError {
  return new SubcCallError('terminal', `terminal ${code}`, code)
}

afterEach(async () => {
  if (originalConnection === undefined) delete process.env.CLAUSTRUM_SUBC_CONNECTION
  else process.env.CLAUSTRUM_SUBC_CONNECTION = originalConnection
  if (originalModuleId === undefined) delete process.env.SUBC_MODULE_ID
  else process.env.SUBC_MODULE_ID = originalModuleId
  if (originalLaunchNonce === undefined) delete process.env.SUBC_LAUNCH_NONCE
  else process.env.SUBC_LAUNCH_NONCE = originalLaunchNonce
  if (originalXdgRuntime === undefined) delete process.env.XDG_RUNTIME_DIR
  else process.env.XDG_RUNTIME_DIR = originalXdgRuntime
  if (originalHome === undefined) delete process.env.HOME
  else process.env.HOME = originalHome
  if (originalTmpdir === undefined) delete process.env.TMPDIR
  else process.env.TMPDIR = originalTmpdir
  await Promise.all(tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })))
})

describe('ClaustrumClient', () => {
  test('default connection path honours CLAUSTRUM_SUBC_CONNECTION then the subc default', async () => {
    const configured = '/tmp/configured-subc-connection.json'
    const configuredCalls: string[] = []
    process.env.CLAUSTRUM_SUBC_CONNECTION = configured
    const configuredClient = await ClaustrumClient.connect({
      connector: async ({ connectionFile }) => {
        configuredCalls.push(connectionFile)
        return new FakeDaemon() as never
      },
    })
    configuredClient.close()

    delete process.env.CLAUSTRUM_SUBC_CONNECTION
    const defaultCalls: string[] = []
    const defaultClient = await ClaustrumClient.connect({
      connector: async ({ connectionFile }) => {
        defaultCalls.push(connectionFile)
        return new FakeDaemon() as never
      },
    })
    defaultClient.close()

    expect(configuredCalls).toEqual([configured])
    expect(defaultCalls).toEqual([getDefaultClaustrumConnectionPath()])
  })

  test('detection is inert for absent and malformed files', async () => {
    const absentPath = await tempPath('absent.json')
    const malformedPath = await tempPath('malformed.json')
    let connections = 0
    const daemon = createServer(() => {
      connections += 1
    })
    await new Promise<void>((resolve, reject) => {
      daemon.once('error', reject)
      daemon.listen(0, '127.0.0.1', () => resolve())
    })
    const address = daemon.address()
    if (!address || typeof address === 'string') throw new Error('fake daemon has no TCP address')
    await writeFile(malformedPath, JSON.stringify({
      schema: 'wrong',
      wire_version: 1,
      endpoints: [{ host: '127.0.0.1', port: address.port }],
    }))

    expect(await detectClaustrumConnection(absentPath)).toEqual({
      status: 'absent',
      path: absentPath,
    })
    expect(await detectClaustrumConnection(malformedPath)).toMatchObject({
      status: 'malformed',
      path: malformedPath,
    })
    expect(connections).toBe(0)
    await new Promise<void>((resolve) => daemon.close(() => resolve()))
  })

  test('accepts a legacy connection file that omits the additive wire version', async () => {
    const path = await tempPath('legacy-connection.json')
    await writeFile(path, JSON.stringify({
      schema: 1,
      endpoints: [{ host: '127.0.0.1', port: 8765 }],
      key: Array.from({ length: 32 }, () => 1),
      daemon_id: Array.from({ length: 16 }, () => 2),
      pid: 1,
      daemon_ver: 'legacy',
    }))
    await chmod(path, 0o600)

    await expect(detectClaustrumConnection(path)).resolves.toMatchObject({
      status: 'available',
      schema: 1,
      endpoints: [{ host: '127.0.0.1', port: 8765 }],
    })
  })

  test('never echoes connection-file key material from a JSON parse failure', async () => {
    const path = await tempPath('secret-parse.json')
    const key = 'k'.repeat(40)
    await writeFile(path, `{"key": ${key}}`)

    const result = await detectClaustrumConnection(path)

    expect(result).toEqual(expect.objectContaining({ status: 'malformed', reason: 'connection file could not be read or validated' }))
    expect(JSON.stringify(result)).not.toContain(key)
  })

  test('default discovery mirrors the daemon order: XDG_RUNTIME_DIR, then production home, then temp glob', async () => {
    // Daemon writes `subc-<token>.connection.json` where token derives from a uid-probe
    // (unix), a sanitized USER/USERNAME/HOME/USERPROFILE, or `'unknown'`. On macOS where
    // XDG_RUNTIME_DIR is unset the daemon falls into the sanitized-user branch, so its
    // filename does NOT match the client's `subc-${uid}.connection.json` literal.
    const tempRoot = await mkdtemp(join(tmpdir(), 'claustrum-discover-'))
    tempDirs.push(tempRoot)

    const homeDir = join(tempRoot, 'home')
    const fixtureTmp = join(tempRoot, 'tmp')
    await mkdir(homeDir, { recursive: true })
    await mkdir(fixtureTmp, { recursive: true })

    const token = `rediscovery-${Date.now()}-${process.pid}`
    const daemonFile = join(fixtureTmp, `subc-${token}.connection.json`)
    await writeFile(daemonFile, JSON.stringify({
      schema: 1,
      wire_version: PROTOCOL_VERSION,
      endpoints: [{ host: '127.0.0.1', port: 8765 }],
      key: Array.from({ length: 32 }, () => 1),
      daemon_id: Array.from({ length: 16 }, () => 2),
      pid: 1,
      daemon_ver: 'test',
    }))
    await chmod(daemonFile, 0o600)
    delete process.env.XDG_RUNTIME_DIR
    process.env.HOME = homeDir
    process.env.TMPDIR = fixtureTmp

    try {
      expect(getDefaultClaustrumConnectionPath()).toBe(daemonFile)
    } finally {
      await rm(daemonFile, { force: true })
    }
  })

  test('default discovery uses process.env.HOME exactly for the home tier, not userInfo().homedir', async () => {
    // P1: the Rust `discover_subc_connection_file` resolves the home tier from
    // `non_empty_env("HOME")` directly — no `getpwuid`-style fallback. The client must
    // mirror this byte-for-byte: when HOME contains a trailing space and points to a
    // fixture dir holding a production connection file, the client returns that file
    // rather than the trimmed path or the real user's
    // ~/.local/share/cortexkit/run/subc-connection.json. Without the mirror, an
    // override is silently ignored and a daemon started under the test fixture is
    // unreachable, leaving vault-backed requests dead.
    const tempRoot = await mkdtemp(join(tmpdir(), 'claustrum-home-override-'))
    tempDirs.push(tempRoot)
    const homeDir = join(tempRoot, 'home ')
    await mkdir(homeDir, { recursive: true })
    const fixtureTmp = join(tempRoot, 'tmp')
    await mkdir(fixtureTmp, { recursive: true })
    const runDir = join(homeDir, '.local', 'share', 'cortexkit', 'run')
    await mkdir(runDir, { recursive: true })
    const fixtureFile = join(runDir, 'subc-connection.json')
    await writeFile(fixtureFile, JSON.stringify({
      schema: 1,
      wire_version: PROTOCOL_VERSION,
      endpoints: [{ host: '127.0.0.1', port: 8765 }],
      key: Array.from({ length: 32 }, () => 3),
      daemon_id: Array.from({ length: 16 }, () => 4),
      pid: 3,
      daemon_ver: 'home-override',
    }))
    await chmod(fixtureFile, 0o600)

    delete process.env.XDG_RUNTIME_DIR
    process.env.HOME = homeDir
    process.env.TMPDIR = fixtureTmp

    try {
      expect(getDefaultClaustrumConnectionPath()).toBe(fixtureFile)
    } finally {
      await rm(fixtureFile, { force: true })
    }
  })

  test('default discovery refuses ambiguity when multiple connection files share the temp dir', async () => {
    const tempRoot = await mkdtemp(join(tmpdir(), 'claustrum-ambiguous-'))
    tempDirs.push(tempRoot)
    const fixtureTmp = join(tempRoot, 'tmp')
    await mkdir(fixtureTmp, { recursive: true })
    const a = join(fixtureTmp, `subc-ambiguous-a-${process.pid}-${Date.now()}.connection.json`)
    const b = join(fixtureTmp, `subc-ambiguous-b-${process.pid}-${Date.now()}.connection.json`)
    await writeFile(a, '{"schema":1}')
    await writeFile(b, '{"schema":1}')

    delete process.env.XDG_RUNTIME_DIR
    const homeDir = join(tempRoot, 'home')
    await mkdir(homeDir, { recursive: true })
    process.env.HOME = homeDir
    process.env.TMPDIR = fixtureTmp

    try {
      const path = getDefaultClaustrumConnectionPath()
      expect([a, b]).not.toContain(path)
    } finally {
      await rm(a, { force: true })
      await rm(b, { force: true })
    }
  })

  test('detection reports the connection file wire_version when it matches the client build', async () => {
    const path = await tempPath('wire-version.json')
    await writeFile(path, JSON.stringify({
      schema: 1,
      wire_version: PROTOCOL_VERSION,
      endpoints: [{ host: '127.0.0.1', port: 8765 }],
      key: Array.from({ length: 32 }, () => 1),
      daemon_id: Array.from({ length: 16 }, () => 2),
      pid: 1,
      daemon_ver: 'mod',
    }))
    await chmod(path, 0o600)

    const result = await detectClaustrumConnection(path)
    expect(result).toMatchObject({ status: 'available', wireVersion: PROTOCOL_VERSION })
  })

  test('identity scrubs inherited SUBC_MODULE_ID and SUBC_LAUNCH_NONCE then hashes the store path', async () => {
    // The symlink fixture requires `SeCreateSymbolicLinkPrivilege` on Windows
    // and is not part of the platform support contract. The Windows subset in
    // ci.yml still runs `bun test packages/client`; a one-line skip keeps the
    // leg honest without gating the test off the windows arm at the file level.
    if (process.platform === 'win32') {
      console.warn('SKIP identity/symlink: symlink() on Windows requires SeCreateSymbolicLinkPrivilege; not part of platform support contract')
      return
    }
    process.env.SUBC_MODULE_ID = 'inherited-module'
    process.env.SUBC_LAUNCH_NONCE = 'inherited-nonce'
    const storagePath = await tempPath('store.db')
    const linkedStoragePath = join(dirname(storagePath), 'store-link.db')
    await writeFile(storagePath, '')
    await symlink(storagePath, linkedStoragePath)
    const daemon = new FakeDaemon([
      { result: { payload: [111, 107], record_version: 7 } },
    ])
    const client = await ClaustrumClient.connect({
      projectRoot: '/project/root',
      storagePath: linkedStoragePath,
      connector: async () => daemon as never,
    })

    await client.getCredential('credential-handle')

    const expectedFingerprint = createHash('sha256')
      .update(await realpath(linkedStoragePath))
      .digest('hex')
    expect(daemon.calls[0]).toMatchObject({
      options: {
        consumerIdentity: null,
        identity: {
          project_root: '/project/root',
          harness: 'opencode',
          session: `store-${expectedFingerprint}`,
        },
      },
    })
    client.close()
  })

  test('configured connection path is threaded to the transport', async () => {
    const connectionFile = '/tmp/explicit-subc-connection.json'
    const calls: string[] = []
    const client = await ClaustrumClient.connect({
      connectionFile,
      connector: async ({ connectionFile: received }) => {
        calls.push(received)
        return new FakeDaemon() as never
      },
    })

    expect(calls).toEqual([connectionFile])
    client.close()
  })

  test('reconnects once after terminal route failure but not missing_identity or invalid_control_body', async () => {
    const first = new FakeDaemon([], terminal('route_wedged'))
    const second = new FakeDaemon([
      { result: { payload: [111, 107], record_version: 9 } },
      { result: { payload: [111, 107], record_version: 9 } },
    ])
    let connects = 0
    const client = await ClaustrumClient.connect({
      connector: async () => (++connects === 1 ? first : second) as never,
    })

    await expect(
      Promise.all([client.getCredential('a'), client.getCredential('b')]),
    ).resolves.toHaveLength(2)
    expect(connects).toBe(2)
    expect(first.closed).toBe(true)

    for (const code of ['missing_identity', 'invalid_control_body']) {
      let prohibitedReconnects = 0
      const nonReconnectClient = await ClaustrumClient.connect({
        connector: async () => {
          prohibitedReconnects += 1
          return new FakeDaemon([], terminal(code)) as never
        },
      })
      await expect(nonReconnectClient.getCredential(code)).rejects.toMatchObject({ code })
      expect(prohibitedReconnects).toBe(1)
      nonReconnectClient.close()
    }
    client.close()
  })

  test('decodes nested error classes and maps them to actions', async () => {
    const cases = [
      ['not_found', 'permanent', 'gone'],
      ['needs_login', 'auth_required', 'reauth'],
      ['temporary', 'transient', 'retry'],
      ['too_large', 'context_overflow', 'reduce_and_retry'],
    ] as const
    for (const [code, errorClass, action] of cases) {
      const client = await ClaustrumClient.connect({
        connector: async () =>
          new FakeDaemon([{ result: { error: { class: errorClass, code } } }]) as never,
      })
      await expect(client.getCredential('credential-handle')).rejects.toMatchObject({
        code,
        class: errorClass,
        action,
      })
      client.close()
    }
  })

  test('treats an envelope that omits code as malformed and falls back to transient', async () => {
    // P2: the wire contract in read_surface.rs says BOTH `class` and `code` are always
    // present. A frame missing `code` is therefore malformed; treating its `class`
    // as authoritative lets a malicious or broken peer drive a "gone" action (the
    // mapping of `permanent`) by sending a half-formed error. The cut-line rule
    // (Anthropic: unknown or absent class → transient) is the safer fallback: a
    // malformed envelope is treated as transient and retried.
    const client = await ClaustrumClient.connect({
      connector: async () =>
        new FakeDaemon([
          { result: { error: { class: 'permanent' } } },
        ]) as never,
    })

    await expect(client.getCredential('credential-handle')).rejects.toMatchObject({
      code: 'invalid_response',
      class: 'transient',
      action: 'retry',
    })
    client.close()
  })

  test('bounds an UNKNOWN error class to transient and logs only the class name', async () => {
    const logs: string[] = []
    const client = await ClaustrumClient.connect({
      logger: (errorClass) => logs.push(errorClass),
      connector: async () =>
        new FakeDaemon([
          { result: { error: { class: 'future_class', code: 'future_code' } } },
        ]) as never,
    })

    await expect(client.getCredential('private-handle')).rejects.toMatchObject({
      code: 'future_code',
      class: 'transient',
      action: 'retry',
    })
    expect(logs).toEqual(['future_class'])
    client.close()
  })

  test('emits exact get, status, and report request shapes to the fake daemon', async () => {
    const daemon = new FakeDaemon([
      { result: { payload: [111, 107], expires_at_ms: 1_000, record_version: 63 } },
      { result: { ready: true, last_error_code: null, lease_held: true, record_version: 63 } },
      { result: { accepted: true } },
    ])
    const client = await ClaustrumClient.connect({ connector: async () => daemon as never })

    await client.getCredential('h_1', 42_000)
    await client.statusCredential('h_1')
    await client.reportAuthFailure({
      handle: 'h_1',
      providerStatus: 401,
      recordVersion: 63,
      reporterSource: 'relay_message_parse',
    })

    expect(daemon.calls.map(({ moduleId, method, params }) => ({ moduleId, method, params }))).toEqual([
      {
        moduleId: 'claustrum',
        method: 'credential.get',
        params: { handle: 'h_1', min_ttl_ms: 42_000, force_refresh: false },
      },
      {
        moduleId: 'claustrum',
        method: 'credential.status',
        params: { handle: 'h_1' },
      },
      {
        moduleId: 'claustrum',
        method: 'credential.report_auth_failure',
        params: {
          handle: 'h_1',
          provider_status: 401,
          record_version: 63,
          reporter_source: 'relay_message_parse',
        },
      },
    ])
    client.close()
  })

  test('rejects a report response that does not explicitly acknowledge acceptance', async () => {
    const client = await ClaustrumClient.connect({
      connector: async () => new FakeDaemon([{ result: { accepted: false } }]) as never,
    })

    await expect(client.reportAuthFailure({
      handle: 'h_1',
      providerStatus: 401,
      recordVersion: 63,
      reporterSource: 'direct',
    })).rejects.toMatchObject({ code: 'invalid_response' })
    client.close()
  })
})
