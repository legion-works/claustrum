import {
  defaultHandleFilePath,
  handleFileRevision as clientHandleFileRevision,
  parseHandleFile as clientParseHandleFile,
  readHandleFile as clientReadHandleFile,
  type HandleFileIo,
  type OpenCodeHandleFileV1,
} from '@cortexkit/claustrum-client'
import { HandleFileValidationError } from './errors'

export { defaultHandleFilePath }
export type { HandleFileIo, OpenCodeHandleFileV1 }
export const OUR_PLUGIN_ID = 'opencode-claustrum'

function preserveError<T>(operation: () => T): T {
  try { return operation() } catch (error) {
    if (error instanceof Error && error.name === 'HandleFileValidationError') throw new HandleFileValidationError(error.message)
    throw error
  }
}

export function parseHandleFile(value: unknown): OpenCodeHandleFileV1 { return preserveError(() => clientParseHandleFile(value)) }
export async function readHandleFile(path?: string, io?: HandleFileIo): Promise<OpenCodeHandleFileV1> {
  try { return await clientReadHandleFile(path, io) } catch (error) {
    if (error instanceof Error && error.name === 'HandleFileValidationError') throw new HandleFileValidationError(error.message)
    throw error
  }
}
export async function handleFileRevision(path?: string, io?: HandleFileIo): Promise<string> {
  try { return await clientHandleFileRevision(path, io) } catch (error) {
    if (error instanceof Error && error.name === 'HandleFileValidationError') throw new HandleFileValidationError(error.message)
    throw error
  }
}
