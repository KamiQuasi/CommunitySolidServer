import type { CredentialSet } from '../authentication/Credentials';
import { AsyncHandler } from '../util/handlers/AsyncHandler';
import type { AccessMap, PermissionMap } from './permissions/Permissions';

export interface AuthorizerInput {
  /**
   * Credentials of the entity that wants to use the resource.
   */
  credentials: CredentialSet;
  /**
   * Modes that are requested on the resource.
   */
  accessMap: AccessMap;
  /**
   * Permissions that are available for the request.
   */
  permissionMap: PermissionMap;
}

/**
 * Verifies if the credentials provide access with the given permissions on the resource.
 * An {@link Error} with the necessary explanation will be thrown when permissions are not granted.
 */
export abstract class Authorizer extends AsyncHandler<AuthorizerInput> {}
