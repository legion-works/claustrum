export {
  detectClaustrumConnection,
  getDefaultClaustrumConnectionPath,
  resolveClaustrumConnectionPath,
  type ClaustrumDetection,
  type ClaustrumEndpoint,
} from './detect.js'
export { storeIdentity, storageFingerprint } from './identity.js'
export {
  MANIFEST_LOCK,
  withManifestLock,
  writeHandleFileLocked,
  type ManifestHandleAccount,
  type ManifestHandleFile,
  type ManifestHandleProvider,
} from './manifest-lock.js'
export {
  ClaustrumCredentialError,
  credentialErrorAction,
  ERROR_CLASS_WIRE_SET,
  type ClaustrumCredentialErrorAction,
  type ClaustrumCredentialErrorClass,
} from './errors.js'
export {
  ClaustrumClient,
  type ClaustrumClientOptions,
  type ClaustrumConnector,
  type ClaustrumReporterSource,
  type CredentialStatus,
  type ServedCredential,
} from './wire.js'
export {
  HANDLE_FILE_CONTRACT,
  HandleFileValidationError,
  defaultHandleFilePath,
  handleFileRevision,
  parseHandleFile,
  readHandleFile,
  type HandleAccount,
  type HandleFileIo,
  type HandleProvider,
  type OpenCodeHandleFileV1,
} from './handles.js'
