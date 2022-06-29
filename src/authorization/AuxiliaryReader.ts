import type { AuxiliaryStrategy } from '../http/auxiliary/AuxiliaryStrategy';
import type { ResourceIdentifier } from '../http/representation/ResourceIdentifier';
import { getLoggerFor } from '../logging/LogUtil';
import type { PermissionReaderInput } from './PermissionReader';
import { PermissionReader } from './PermissionReader';
import type { AccessMap, AccessMode, PermissionMap } from './permissions/Permissions';
import { updateAccessMap } from './permissions/PermissionUtil';

/**
 * Determines the permissions of auxiliary resources by finding those of the corresponding subject resources.
 */
export class AuxiliaryReader extends PermissionReader {
  protected readonly logger = getLoggerFor(this);

  private readonly reader: PermissionReader;
  private readonly auxiliaryStrategy: AuxiliaryStrategy;

  public constructor(reader: PermissionReader, auxiliaryStrategy: AuxiliaryStrategy) {
    super();
    this.reader = reader;
    this.auxiliaryStrategy = auxiliaryStrategy;
  }

  public async handle({ accessMap, credentials }: PermissionReaderInput): Promise<PermissionMap> {
    const auxMap = new Map(this.findAuxiliary(accessMap));

    // No need to transform if there are no changes
    if (auxMap.size === 0) {
      return this.reader.handleSafe({ accessMap, credentials });
    }

    const updatedMap = updateAccessMap(auxMap.values(), new Set(auxMap.keys()), accessMap);
    const result = await this.reader.handleSafe({ accessMap: updatedMap, credentials });

    for (const [ identifier, [ subject ]] of auxMap) {
      this.logger.debug(`Mapping ${subject.path} permissions to ${identifier.path}`);
      result.set(identifier, result.get(subject) ?? {});
    }
    return result;
  }

  /**
   * Maps auxiliary resources that do not have their own authorization checks to their subject resource.
   */
  private* findAuxiliary(accessMap: AccessMap): Iterable<[ResourceIdentifier, [ResourceIdentifier, Set<AccessMode>]]> {
    for (const [ identifier, modes ] of accessMap) {
      if (this.auxiliaryStrategy.isAuxiliaryIdentifier(identifier) &&
        !this.auxiliaryStrategy.usesOwnAuthorization(identifier)) {
        yield [ identifier, [ this.auxiliaryStrategy.getSubjectIdentifier(identifier), modes ]];
      }
    }
  }
}
