import { afterEach, describe, expect, test } from 'bun:test'
import { chmod, mkdir, rm, symlink, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import {
  HANDLE_FILE_CONTRACT,
  defaultHandleFilePath,
  handleFileRevision,
  parseHandleFile,
  readHandleFile,
  type OpenCodeHandleFileV1,
} from '../handles.js'

const root = '/tmp/claustrum-client-handles-tests'
const handle = `ckh_${'a'.repeat(43)}`

afterEach(() => rm(root, { recursive: true, force: true }))

function validFile(): OpenCodeHandleFileV1 {
  return { version: 1, providers: [{ provider: 'deepseek', shape: 'api', serve: 'opencode-claustrum', accounts: [{ label: 'main', handle, credential_id: 'apikey:deepseek:main' }] }] }
}

describe('client handle-file contract', () => {
  test('exports the pinned resolver and contract constants', () => {
    expect(defaultHandleFilePath({ CLAUSTRUM_OPENCODE_HANDLES: '/tmp/custom.json' })).toBe('/tmp/custom.json')
    expect(HANDLE_FILE_CONTRACT.maxBytes).toBe(262144)
    expect(HANDLE_FILE_CONTRACT.mode).toBe(0o600)
    expect(HANDLE_FILE_CONTRACT.labelRe.test('main.account-1')).toBe(true)
    expect(HANDLE_FILE_CONTRACT.handleRe.test(handle)).toBe(true)
  })

  test('reads a valid owned 0600 manifest and computes its revision', async () => {
    await mkdir(root, { recursive: true, mode: 0o700 })
    const path = join(root, 'handles.json')
    await writeFile(path, `${JSON.stringify(validFile())}\n`, { mode: 0o600 })
    expect(await readHandleFile(path)).toEqual(validFile())
    expect(await handleFileRevision(path)).toMatch(/^\d+(\.\d+)?:\w{64}$/)
  })

  test('rejects insecure mode and world-writable parents', async () => {
    await mkdir(root, { recursive: true, mode: 0o777 })
    const path = join(root, 'handles.json')
    await writeFile(path, JSON.stringify(validFile()), { mode: 0o600 })
    await chmod(root, 0o777)
    await expect(readHandleFile(path)).rejects.toThrow('world-writable without sticky bit')
    await chmod(root, 0o700)
    await chmod(path, 0o640)
    await expect(readHandleFile(path)).rejects.toThrow('exactly 0600')
  })

  test('rejects invalid labels, handles, prototype keys, and oversized input', async () => {
    expect(() => parseHandleFile({ version: 1, providers: [{ ...validFile().providers[0], accounts: [{ ...validFile().providers[0].accounts[0], label: '__proto__' }] }] })).toThrow('invalid account label')
    expect(() => parseHandleFile({ version: 1, providers: [{ ...validFile().providers[0], accounts: [{ ...validFile().providers[0].accounts[0], handle: 'ckh_short' }] }] })).toThrow('invalid handle')
    await mkdir(root, { recursive: true, mode: 0o700 })
    const path = join(root, 'handles.json')
    await writeFile(path, 'x'.repeat(262145), { mode: 0o600 })
    await expect(readHandleFile(path)).rejects.toThrow('exceeds 256 KiB')
  })

  test('preserves the historical parser fixture outcomes and exact messages', () => {
    const provider = validFile().providers[0]
    const account = provider.accounts[0]
    const fixtures: Array<[unknown, string]> = [
      [null, 'handle file must be an object'],
      [{ version: 2, providers: [] }, 'handle file must have version 1 and providers'],
      [{ version: 1, providers: [null] }, 'provider 0 must be an object'],
      [{ version: 1, providers: [{ ...provider, provider: '__proto__' }] }, 'provider 0 has invalid provider'],
      [{ version: 1, providers: [provider, provider] }, 'provider 1 duplicates provider deepseek'],
      [{ version: 1, providers: [{ ...provider, shape: 'other' }] }, 'provider 0 has invalid shape'],
      [{ version: 1, providers: [{ ...provider, serve: '' }] }, 'provider 0 requires serve'],
      [{ version: 1, providers: [{ ...provider, accounts: [{ ...account, credential_id: 3 }] }] }, 'provider 0 has invalid accounts'],
      [{ version: 1, providers: [{ ...provider, accounts: [{ ...account, label: '__proto__' }] }] }, 'provider 0 has an invalid account label'],
      [{ version: 1, providers: [{ ...provider, accounts: [account, account] }] }, 'provider 0 duplicates account label main'],
      [{ version: 1, providers: [{ ...provider, accounts: [{ ...account, handle: 'ckh_short' }] }] }, 'provider 0 account main has invalid handle'],
      [{ version: 1, providers: [{ ...provider, accounts: [{ ...account, credential_id: '' }] }] }, 'provider 0 account main has invalid credential id'],
      [{ version: 1, providers: [{ ...provider, accounts: [{ ...account, superseded: ['ckh_short'] }] }] }, 'provider 0 account main has invalid superseded handle'],
    ]
    for (const [fixture, message] of fixtures) expect(() => parseHandleFile(fixture)).toThrow(message)
  })

  test('preserves historical reader validation order and normalized failures', async () => {
    const source = JSON.stringify(validFile())
    const regular = { isFile: () => true, mode: 0o100600, uid: 1000, size: source.length }
    const parent = { isFile: () => false, isDirectory: () => true, mode: 0o040755, uid: 1000 }
    await expect(readHandleFile('/tmp/handles.json', {
      currentUid: () => 1000,
      lstat: async () => regular,
      stat: async () => { throw new Error('parent denied') },
      readFile: async () => source,
    })).rejects.toThrow('cannot stat handle file parent: parent denied')
    await expect(readHandleFile('/tmp/handles.json', {
      currentUid: () => 1000,
      lstat: async () => regular,
      stat: async () => parent,
      readFile: async () => { throw new Error('read denied') },
    })).rejects.toThrow('cannot read handle file: read denied')
    await expect(readHandleFile('/tmp/handles.json', {
      currentUid: () => 1000,
      lstat: async () => ({ ...regular, mode: 0o100640, uid: 1001 }),
      stat: async () => { throw new Error('must not reach parent') },
      readFile: async () => { throw new Error('must not read') },
    })).rejects.toThrow('handle file mode must be exactly 0600')
  })

  test('preserves the historical symlink and grow-after-fstat fixture outcomes', async () => {
    await mkdir(root, { recursive: true, mode: 0o700 })
    const target = join(root, 'target.json')
    const link = join(root, 'handles.json')
    await writeFile(target, JSON.stringify(validFile()), { mode: 0o600 })
    await symlink(target, link)
    await expect(readHandleFile(link)).rejects.toThrow('handle file must not be a symlink')

    const chunk = Buffer.alloc(HANDLE_FILE_CONTRACT.maxBytes + 2, 0x78)
    await expect(readHandleFile('/tmp/handles.json', {
      currentUid: () => 1000,
      stat: async () => ({ isFile: () => false, isDirectory: () => true, mode: 0o040755, uid: 1000 }),
      open: async () => ({
        stat: async () => ({ isFile: () => true, mode: 0o100600, uid: 1000, size: 256 }),
        readFile: async () => chunk.toString('utf8'),
        read: (buffer, offset, length, position) => {
          const remaining = chunk.length - position
          if (remaining <= 0) return { bytesRead: 0 }
          const slice = chunk.subarray(position, position + Math.min(length, remaining))
          buffer.set(slice, offset)
          return { bytesRead: slice.length }
        },
        close: async () => {},
      }),
    })).rejects.toThrow('handle file exceeds 256 KiB')
  })

  test('keeps the contract regex definitions in the client package only', async () => {
    const source = await Bun.file(join(import.meta.dir, '../../../opencode/src/plugin.ts')).text()
    const manifestLock = await Bun.file(join(import.meta.dir, '../manifest-lock.ts')).text()
    expect(source).not.toContain('SCANNED_PROVIDER_ID = /^[a-z0-9][a-z0-9._-]{0,63}$/')
    expect(source).toContain('HANDLE_FILE_CONTRACT')
    expect(manifestLock).toContain('HANDLE_FILE_CONTRACT.maxBytes')
    expect(manifestLock).not.toContain('262144')
  })
})
