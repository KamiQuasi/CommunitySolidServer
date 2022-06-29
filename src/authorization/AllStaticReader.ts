import type { CredentialGroup, CredentialSet } from '../authentication/Credentials';
import type { ResourceIdentifier } from '../http/representation/ResourceIdentifier';
import { mapIterable } from '../util/IterableUtil';
import type { PermissionReaderInput } from './PermissionReader';
import { PermissionReader } from './PermissionReader';
import type { Permission, PermissionMap, PermissionSet } from './permissions/Permissions';
import { IdentifierMap } from './permissions/Permissions';

/**
 * PermissionReader which sets all permissions to true or false
 * independently of the identifier and requested permissions.
 */
export class AllStaticReader extends PermissionReader {
  private readonly permissions: Permission;

  public constructor(allow: boolean) {
    super();
    this.permissions = Object.freeze({
      read: allow,
      write: allow,
      append: allow,
      create: allow,
      delete: allow,
    });
  }

  public async handle({ credentials, accessMap }: PermissionReaderInput): Promise<PermissionMap> {
    const entries = mapIterable(
      accessMap.keys(),
      (identifier): [ResourceIdentifier, PermissionSet] => [ identifier, this.mapCredentials(credentials) ],
    );

    return new IdentifierMap(entries);
  }

  // Create a new PermissionSet for every entry to prevent accidental changes further down the line
  private mapCredentials(credentials: CredentialSet): PermissionSet {
    const result: PermissionSet = {};
    for (const group of Object.keys(credentials) as CredentialGroup[]) {
      result[group] = this.permissions;
    }
    return result;
  }
}
