import type { CredentialSet } from '../authentication/Credentials';
import { AsyncHandler } from '../util/handlers/AsyncHandler';
import type { AccessMap, PermissionMap } from './permissions/Permissions';

export interface PermissionReaderInput {
  /**
   * Credentials of the entity that wants to use the resource.
   */
  credentials: CredentialSet;
  /**
   * This is the minimum set of access modes the output needs to contain per resource,
   * allowing the handler to limit its search space to this set.
   * However, non-exhaustive information about other access modes and resources can still be returned.
   */
  accessMap: AccessMap;
}

/**
 * Discovers the permissions of the given credentials on the given identifier.
 * In case the reader finds no permission for the requested identifiers and credentials
 * it can return an empty or incomplete map.
 */
export abstract class PermissionReader extends AsyncHandler<PermissionReaderInput, PermissionMap> {}
