export {
  detectClaustrumConnection,
  getDefaultClaustrumConnectionPath,
  resolveClaustrumConnectionPath,
  type ClaustrumDetection,
  type ClaustrumEndpoint,
} from './detect.js'
export { storeIdentity, storageFingerprint } from './identity.js'
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
