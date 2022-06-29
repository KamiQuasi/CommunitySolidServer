import type { CredentialGroup } from '../authentication/Credentials';
import { UnionHandler } from '../util/handlers/UnionHandler';
import type { PermissionReader } from './PermissionReader';
import type { Permission, PermissionMap } from './permissions/Permissions';
import { IdentifierMap } from './permissions/Permissions';

/**
 * Combines the results of multiple PermissionReaders.
 * Every permission in every credential type is handled according to the rule `false` \> `true` \> `undefined`.
 */
export class UnionPermissionReader extends UnionHandler<PermissionReader> {
  public constructor(readers: PermissionReader[]) {
    super(readers);
  }

  protected async combine(results: PermissionMap[]): Promise<PermissionMap> {
    const result: PermissionMap = new IdentifierMap();
    for (const permissionMap of results) {
      this.applyPermissionMap(permissionMap, result);
    }
    return result;
  }

  /**
   * Applies all entries of the given map to the result map.
   */
  private applyPermissionMap(permissionMap: PermissionMap, result: PermissionMap): void {
    for (const [ identifier, permissionSet ] of permissionMap) {
      for (const [ credential, permission ] of Object.entries(permissionSet) as [CredentialGroup, Permission][]) {
        let resultSet = result.get(identifier);
        if (!resultSet) {
          resultSet = {};
          result.set(identifier, resultSet);
        }
        resultSet[credential] = this.applyPermissions(permission, resultSet[credential]);
      }
    }
  }

  /**
   * Adds the given permissions to the result object according to the combination rules of the class.
   */
  private applyPermissions(permissions?: Permission, result: Permission = {}): Permission {
    if (!permissions) {
      return result;
    }

    for (const [ key, value ] of Object.entries(permissions) as [ keyof Permission, boolean | undefined ][]) {
      if (typeof value !== 'undefined' && result[key] !== false) {
        result[key] = value;
      }
    }
    return result;
  }
}
