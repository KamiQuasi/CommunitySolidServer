import type { CredentialGroup } from '../authentication/Credentials';
import type { ResourceIdentifier } from '../http/representation/ResourceIdentifier';
import { getLoggerFor } from '../logging/LogUtil';
import type { IdentifierStrategy } from '../util/identifiers/IdentifierStrategy';
import type { PermissionReaderInput } from './PermissionReader';
import { PermissionReader } from './PermissionReader';
import type { PermissionMap, Permission, PermissionSet, AccessMap } from './permissions/Permissions';
import { AccessMode } from './permissions/Permissions';
import { updateAccessMap } from './permissions/PermissionUtil';

/**
 * Determines `delete` and `create` permissions for those resources that need it
 * by making sure the parent container has the required permissions.
 *
 * Create requires `append` permissions on the parent container.
 * Delete requires `write` permissions on both the parent container and the resource itself.
 */
export class ParentContainerReader extends PermissionReader {
  protected readonly logger = getLoggerFor(this);

  private readonly reader: PermissionReader;
  private readonly identifierStrategy: IdentifierStrategy;

  public constructor(reader: PermissionReader, identifierStrategy: IdentifierStrategy) {
    super();
    this.reader = reader;
    this.identifierStrategy = identifierStrategy;
  }

  public async handle({ accessMap, credentials }: PermissionReaderInput): Promise<PermissionMap> {
    const containerMap = new Map(this.findParents(accessMap));

    // No need to transform if there are no changes
    if (containerMap.size === 0) {
      return this.reader.handleSafe({ accessMap, credentials });
    }

    const updatedMap = updateAccessMap(containerMap.values(), new Set(), accessMap);
    const result = await this.reader.handleSafe({ accessMap: updatedMap, credentials });

    for (const [ identifier, [ container ]] of containerMap) {
      this.logger.debug(`Determining ${identifier.path} create and delete permissions based on ${container.path}`);
      result.set(identifier, this.updatePermission(result.get(identifier), result.get(container)));
    }
    return result;
  }

  private* findParents(accessMap: AccessMap): Iterable<[ResourceIdentifier, [ResourceIdentifier, Set<AccessMode>]]> {
    for (const [ identifier, modes ] of accessMap) {
      if (modes.has(AccessMode.create) || modes.has(AccessMode.delete)) {
        const containerModes: Set<AccessMode> = new Set();
        if (modes.has(AccessMode.create)) {
          containerModes.add(AccessMode.append);
        }
        if (modes.has(AccessMode.delete)) {
          containerModes.add(AccessMode.write);
        }
        const container = this.identifierStrategy.getParentContainer(identifier);
        yield [ identifier, [ container, containerModes ]];
      }
    }
  }

  /**
   * Determines the create and delete permissions for the given permission set based on those if its parent container.
   */
  private updatePermission(permissionSet?: PermissionSet, containerSet?: PermissionSet): PermissionSet {
    permissionSet = { ...permissionSet };
    containerSet = containerSet ?? {};
    for (const [ group, containerPermissions ] of Object.entries(containerSet) as [ CredentialGroup, Permission ][]) {
      const permissions = permissionSet[group] ?? {};
      permissionSet[group] = permissions;

      // https://solidproject.org/TR/2021/wac-20210711:
      // When an operation requests to create a resource as a member of a container resource,
      // the server MUST match an Authorization allowing the acl:Append or acl:Write access privilege
      // on the container for new members.
      permissions.create = containerPermissions.append && permissions.create !== false;

      // https://solidproject.org/TR/2021/wac-20210711:
      // When an operation requests to delete a resource,
      // the server MUST match Authorizations allowing the acl:Write access privilege
      // on the resource and the containing container.
      permissions.delete = permissions.write && containerPermissions.write && permissions.delete !== false;
    }
    return permissionSet;
  }
}
