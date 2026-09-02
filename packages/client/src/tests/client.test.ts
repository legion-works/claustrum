import { afterEach, describe, expect, test } from 'bun:test'
import { createHash } from 'node:crypto'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { createServer } from 'node:net'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { SubcCallError } from '@cortexkit/subc-client'
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
    expect(defaultCalls[0]).toBe(`/run/user/${process.getuid?.()}/subc-connection.json`)
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

  test('identity scrubs inherited SUBC_MODULE_ID and SUBC_LAUNCH_NONCE then hashes the store path', async () => {
    process.env.SUBC_MODULE_ID = 'inherited-module'
    process.env.SUBC_LAUNCH_NONCE = 'inherited-nonce'
    const storagePath = await tempPath('store.db')
    const daemon = new FakeDaemon([
      { result: { payload: [111, 107], record_version: 7 } },
    ])
    const client = await ClaustrumClient.connect({
      projectRoot: '/project/root',
      storagePath,
      connector: async () => daemon as never,
    })

    await client.getCredential('credential-handle')

    const expectedFingerprint = createHash('sha256')
      .update(resolve(storagePath))
      .digest('hex')
      .slice(0, 12)
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
      { result: {} },
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
})
