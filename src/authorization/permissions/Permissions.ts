import type { CredentialGroup } from '../../authentication/Credentials';
import type { ResourceIdentifier } from '../../http/representation/ResourceIdentifier';
import { HashMap } from '../../util/HashMap';

/**
 * Different modes that require permission.
 */
export enum AccessMode {
  read = 'read',
  append = 'append',
  write = 'write',
  create = 'create',
  delete = 'delete',
}

/**
 * A specific implementation of {@link HashMap} where the key type is {@link ResourceIdentifier}.
 */
export class IdentifierMap<T> extends HashMap<ResourceIdentifier, T> {
  public constructor(iterable?: Iterable<readonly [ResourceIdentifier, T]>) {
    super((identifier): string => identifier.path, iterable);
  }
}

/**
 * Access modes per identifier.
 */
export type AccessMap = IdentifierMap<Set<AccessMode>>;

/**
 * A data interface indicating which permissions are required (based on the context).
 */
export type Permission = Partial<Record<AccessMode, boolean>>;

/**
 * Permission per CredentialGroup.
 */
export type PermissionSet = Partial<Record<CredentialGroup, Permission>>;

/**
 * PermissionSet per identifier.
 */
export type PermissionMap = IdentifierMap<PermissionSet>;
