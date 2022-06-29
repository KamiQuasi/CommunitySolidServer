import type { CredentialGroup } from '../authentication/Credentials';
import type { AuxiliaryStrategy } from '../http/auxiliary/AuxiliaryStrategy';
import type { ResourceIdentifier } from '../http/representation/ResourceIdentifier';
import { getLoggerFor } from '../logging/LogUtil';
import type { PermissionReaderInput } from './PermissionReader';
import { PermissionReader } from './PermissionReader';
import { AclMode } from './permissions/AclPermission';
import type { AclPermission } from './permissions/AclPermission';
import type { AccessMap, AccessMode, PermissionMap, PermissionSet } from './permissions/Permissions';
import { updateAccessMap } from './permissions/PermissionUtil';

/**
 * Determines the permission for ACL auxiliary resources.
 * This is done by looking for control permissions on the subject resource.
 */
export class WebAclAuxiliaryReader extends PermissionReader {
  protected readonly logger = getLoggerFor(this);

  private readonly reader: PermissionReader;
  private readonly aclStrategy: AuxiliaryStrategy;

  public constructor(reader: PermissionReader, aclStrategy: AuxiliaryStrategy) {
    super();
    this.reader = reader;
    this.aclStrategy = aclStrategy;
  }

  public async handle({ accessMap, credentials }: PermissionReaderInput): Promise<PermissionMap> {
    const aclMap = new Map(this.findAcl(accessMap));

    // No need to transform if there are no changes
    if (aclMap.size === 0) {
      return this.reader.handleSafe({ accessMap, credentials });
    }

    const updatedMap = updateAccessMap(aclMap.values(), new Set(aclMap.keys()), accessMap);
    const result = await this.reader.handleSafe({ accessMap: updatedMap, credentials });

    for (const [ identifier, [ subject ]] of aclMap) {
      this.logger.debug(`Mapping ${subject.path} control permission to all permissions for ${identifier.path}`);
      result.set(identifier, this.updatePermission(identifier, result.get(subject)));
    }
    return result;
  }

  private* findAcl(accessMap: AccessMap): Iterable<[ResourceIdentifier, [ResourceIdentifier, Set<AccessMode>]]> {
    for (const [ identifier ] of accessMap) {
      if (this.aclStrategy.isAuxiliaryIdentifier(identifier)) {
        const subject = this.aclStrategy.getSubjectIdentifier(identifier);
        // Unfortunately there is no enum inheritance so we have to cast like this
        yield [ identifier, [ subject, new Set([ AclMode.control ] as unknown as AccessMode[]) ]];
      }
    }
  }

  protected updatePermission(identifier: ResourceIdentifier, permissionSet: PermissionSet = {}): PermissionSet {
    const aclSet: PermissionSet = {};
    for (const [ group, permissions ] of Object.entries(permissionSet) as [ CredentialGroup, AclPermission ][]) {
      const { control } = permissions;
      aclSet[group] = {
        read: control,
        append: control,
        write: control,
        control,
      } as AclPermission;
    }
    return aclSet;
  }
}
