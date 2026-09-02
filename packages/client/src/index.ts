export {
  detectClaustrumConnection,
  getDefaultClaustrumConnectionPath,
  resolveClaustrumConnectionPath,
  type ClaustrumDetection,
  type ClaustrumEndpoint,
} from './detect'
export { storeIdentity, storageFingerprint } from './identity'
export {
  ClaustrumCredentialError,
  credentialErrorAction,
  ERROR_CLASS_WIRE_SET,
  type ClaustrumCredentialErrorAction,
  type ClaustrumCredentialErrorClass,
} from './errors'
export {
  ClaustrumClient,
  type ClaustrumClientOptions,
  type ClaustrumConnector,
  type ClaustrumReporterSource,
  type CredentialStatus,
  type ServedCredential,
} from './wire'
