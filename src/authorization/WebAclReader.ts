import { Store } from 'n3';
import type { Credential, CredentialSet } from '../authentication/Credentials';
import { CredentialGroup } from '../authentication/Credentials';
import type { AuxiliaryIdentifierStrategy } from '../http/auxiliary/AuxiliaryIdentifierStrategy';
import type { ResourceIdentifier } from '../http/representation/ResourceIdentifier';
import { getLoggerFor } from '../logging/LogUtil';
import type { ResourceStore } from '../storage/ResourceStore';
import { INTERNAL_QUADS } from '../util/ContentTypes';
import { createErrorMessage } from '../util/errors/ErrorUtil';
import { ForbiddenHttpError } from '../util/errors/ForbiddenHttpError';
import { InternalServerError } from '../util/errors/InternalServerError';
import { NotFoundHttpError } from '../util/errors/NotFoundHttpError';
import type { IdentifierStrategy } from '../util/identifiers/IdentifierStrategy';
import { reduceIterable } from '../util/IterableUtil';
import { readableToQuads } from '../util/StreamUtil';
import { ACL, RDF } from '../util/Vocabularies';
import type { AccessChecker } from './access/AccessChecker';
import type { PermissionReaderInput } from './PermissionReader';
import { PermissionReader } from './PermissionReader';
import type { AclPermission } from './permissions/AclPermission';
import { AclMode } from './permissions/AclPermission';
import type { PermissionMap } from './permissions/Permissions';
import { AccessMode, IdentifierMap } from './permissions/Permissions';

// Maps WebACL-specific modes to generic access modes.
const modesMap: Record<string, Readonly<(keyof AclPermission)[]>> = {
  [ACL.Read]: [ AccessMode.read ],
  [ACL.Write]: [ AccessMode.append, AccessMode.write ],
  [ACL.Append]: [ AccessMode.append ],
  [ACL.Control]: [ AclMode.control ],
} as const;

// Utility type for returning found ACL resources
type AclMatch = { store: Store; identifier: ResourceIdentifier };

/**
 * Finds the permissions of a resource as defined in the corresponding ACL resource.
 * Does not make any deductions such as checking parent containers for create permissions
 * or applying control permissions for ACL resources.
 *
 * Specific access checks are done by the provided {@link AccessChecker}.
 */
export class WebAclReader extends PermissionReader {
  protected readonly logger = getLoggerFor(this);

  private readonly aclStrategy: AuxiliaryIdentifierStrategy;
  private readonly aclStore: ResourceStore;
  private readonly identifierStrategy: IdentifierStrategy;
  private readonly accessChecker: AccessChecker;

  public constructor(aclStrategy: AuxiliaryIdentifierStrategy, aclStore: ResourceStore,
    identifierStrategy: IdentifierStrategy, accessChecker: AccessChecker) {
    super();
    this.aclStrategy = aclStrategy;
    this.aclStore = aclStore;
    this.identifierStrategy = identifierStrategy;
    this.accessChecker = accessChecker;
  }

  /**
   * Checks if an agent is allowed to execute the requested actions.
   * Will throw an error if this is not the case.
   * @param input - Relevant data needed to check if access can be granted.
   */
  public async handle({ credentials, accessMap }: PermissionReaderInput): Promise<PermissionMap> {
    // Determine the required access modes
    this.logger.debug(`Retrieving permissions of ${credentials.agent?.webId ?? 'an unknown agent'}`);
    const aclMap = await this.getAclMatches(new Set(accessMap.keys()));
    const storeMap = await this.filterAclMap(aclMap);
    return await this.findPermissions(storeMap, credentials);
  }

  /**
   * Finds the permissions in the provided WebACL quads.
   *
   * Rather than restricting the search to only the required modes,
   * we collect all modes in order to have complete metadata (for instance, for the WAC-Allow header).
   *
   * @param aclMap - A map containing stores of ACL data linked to their relevant identifiers.
   * @param credentials - Credentials to check permissions for.
   */
  private async findPermissions(aclMap: Map<Store, ResourceIdentifier[]>, credentials: CredentialSet):
  Promise<PermissionMap> {
    const result: PermissionMap = new IdentifierMap();
    for (const [ store, aclIdentifiers ] of aclMap) {
      const publicPermissions = await this.determinePermissions(store, credentials.public);
      const agentPermissions = await this.determinePermissions(store, credentials.agent);
      for (const identifier of aclIdentifiers) {
        result.set(identifier, {
          [CredentialGroup.public]: publicPermissions,
          [CredentialGroup.agent]: agentPermissions,
        });
      }
    }

    return result;
  }

  /**
   * Determines the available permissions for the given credentials.
   * Will deny all permissions if credentials are not defined
   * @param acl - Store containing all relevant authorization triples.
   * @param credential - Credentials to find the permissions for.
   */
  private async determinePermissions(acl: Store, credential?: Credential): Promise<AclPermission> {
    const aclPermissions: AclPermission = {};
    if (!credential) {
      return aclPermissions;
    }

    // Apply all ACL rules
    const aclRules = acl.getSubjects(RDF.type, ACL.Authorization, null);
    for (const rule of aclRules) {
      const hasAccess = await this.accessChecker.handleSafe({ acl, rule, credential });
      if (hasAccess) {
        // Set all allowed modes to true
        const modes = acl.getObjects(rule, ACL.mode, null);
        for (const { value: aclMode } of modes) {
          if (aclMode in modesMap) {
            for (const mode of modesMap[aclMode]) {
              aclPermissions[mode] = true;
            }
          }
        }
      }
    }

    return aclPermissions;
  }

  /**
   * Finds the ACL data relevant for all the given resources.
   * The input set will be modified in place.
   *
   * @param targets - Targets to find ACL data for.
   *
   * @returns A map linking ACL resources to the relevant identifiers.
   */
  private async getAclMatches(targets: Set<ResourceIdentifier>): Promise<Map<AclMatch, ResourceIdentifier[]>> {
    this.logger.debug(`Searching ACL data for ${[ ...targets ].map((id): string => id.path).join(', ')}`);

    const storeMap = new Map<AclMatch, ResourceIdentifier[]>();

    // Loop over the targets until we found matching ACL resources for each of them
    while (targets.size > 0) {
      // Start with the longest identifier as the matching ACL might also be relevant for other resources
      const longest = reduceIterable(targets, (long, identifier): ResourceIdentifier =>
        identifier.path.length > long.path.length ? identifier : long, { path: '' });
      const aclMatch = await this.getAclRecursive(longest);
      const matchingIdentifiers: ResourceIdentifier[] = [];
      storeMap.set(aclMatch, matchingIdentifiers);
      // Find all targets that use the found ACL resource for authorization.
      // Specifically, these are the paths that are a substring of the input path and contain the response path.
      for (const target of targets) {
        if (!longest.path.includes(target.path)) {
          continue;
        }

        // Store all matches in the matchingIdentifiers array and remove them from the list of targets.
        // Only need to check length since we already know both paths are a subpath of `long`.
        if (target.path.length >= aclMatch.identifier.path.length) {
          this.logger.debug(`Found ${target.path} ACL information in the ACL resource of ${aclMatch.identifier.path}`);
          matchingIdentifiers.push(target);
          targets.delete(target);
        }
      }
    }

    return storeMap;
  }

  /**
   * For every store/identifier combination it finds the relevant ACL triples for that identifier.
   * This is done in such a way that store results are reused for all matching identifiers.
   * The split is based on the `acl:accessTo` and `acl:default` triples.
   *
   * @param map - Map of matches that need to be filtered.
   */
  private async filterAclMap(map: Map<AclMatch, ResourceIdentifier[]>): Promise<Map<Store, ResourceIdentifier[]>> {
    // For every found store, filter out triples that match for specific identifiers
    const result = new Map<Store, ResourceIdentifier[]>();
    for (const [{ identifier, store }, matchedTargets ] of map) {
      const directIdentifiers: ResourceIdentifier[] = [];
      const indirectIdentifiers: ResourceIdentifier[] = [];
      for (const target of matchedTargets) {
        (target.path === identifier.path ? directIdentifiers : indirectIdentifiers).push(target);
      }
      if (directIdentifiers.length > 0) {
        const direct = await this.filterStore(store, identifier.path, true);
        result.set(direct, directIdentifiers);
      }
      if (indirectIdentifiers.length > 0) {
        const indirect = await this.filterStore(store, identifier.path, false);
        result.set(indirect, indirectIdentifiers);
      }
    }
    return result;
  }

  /**
   * Returns the ACL information that is relevant for the given identifier.
   * This includes a store of triples, and the subject identifier of where the first matching ACL resource was found.
   *
   * Rethrows any non-NotFoundHttpErrors thrown by the ResourceStore.
   *
   * @param identifier - {@link ResourceIdentifier} of which we need the ACL triples.
   *
   * @returns A store containing the relevant ACL triples.
   */
  private async getAclRecursive(identifier: ResourceIdentifier): Promise<AclMatch> {
    // Obtain the direct ACL document for the resource, if it exists
    this.logger.debug(`Trying to read the direct ACL document of ${identifier.path}`);
    try {
      const acl = this.aclStrategy.getAuxiliaryIdentifier(identifier);
      this.logger.debug(`Trying to read the ACL document ${acl.path}`);
      const data = await this.aclStore.getRepresentation(acl, { type: { [INTERNAL_QUADS]: 1 }});
      this.logger.info(`Reading ACL statements from ${acl.path}`);

      const store = await readableToQuads(data.data);
      return { identifier, store };
    } catch (error: unknown) {
      if (NotFoundHttpError.isInstance(error)) {
        this.logger.debug(`No direct ACL document found for ${identifier.path}`);
      } else {
        const message = `Error reading ACL for ${identifier.path}: ${createErrorMessage(error)}`;
        this.logger.error(message);
        throw new InternalServerError(message, { cause: error });
      }
    }

    // Obtain the applicable ACL of the parent container
    this.logger.debug(`Traversing to the parent of ${identifier.path}`);
    if (this.identifierStrategy.isRootContainer(identifier)) {
      this.logger.error(`No ACL document found for root container ${identifier.path}`);
      // Solid, §10.1: "In the event that a server can’t apply an ACL to a resource, it MUST deny access."
      // https://solid.github.io/specification/protocol#web-access-control
      throw new ForbiddenHttpError('No ACL document found for root container');
    }
    const parent = this.identifierStrategy.getParentContainer(identifier);
    return this.getAclRecursive(parent);
  }

  /**
   * Extracts all rules from the store that are relevant for the given target,
   * based on either the `acl:accessTo` or `acl:default` predicates.
   * @param store - Store to filter.
   * @param target - The identifier of which the acl rules need to be known.
   * @param directAcl - If the store contains triples from the direct acl resource of the target or not.
   *                    Determines if `acl:accessTo` or `acl:default` are used.
   *
   * @returns A store containing the relevant triples for the given target.
   */
  private async filterStore(store: Store, target: string, directAcl: boolean): Promise<Store> {
    // Find subjects that occur with a given predicate/object, and collect all their triples
    const subjectData = new Store();
    const subjects = store.getSubjects(directAcl ? ACL.terms.accessTo : ACL.terms.default, target, null);
    for (const subject of subjects) {
      subjectData.addQuads(store.getQuads(subject, null, null, null));
    }
    return subjectData;
  }
}
