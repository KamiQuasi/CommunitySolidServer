import { CredentialGroup } from '../authentication/Credentials';
import type { AuxiliaryIdentifierStrategy } from '../http/auxiliary/AuxiliaryIdentifierStrategy';
import type { AccountStore } from '../identity/account/AccountStore';
import { getLoggerFor } from '../logging/LogUtil';
import { createErrorMessage } from '../util/errors/ErrorUtil';
import { InternalServerError } from '../util/errors/InternalServerError';
import { NotImplementedHttpError } from '../util/errors/NotImplementedHttpError';
import type { PermissionReaderInput } from './PermissionReader';
import { PermissionReader } from './PermissionReader';
import type { AclPermission } from './permissions/AclPermission';
import type { PermissionSet } from './permissions/Permissions';

/**
 * Allows control access if the request is being made by the owner of the pod containing the resource.
 */
export class OwnerPermissionReader extends PermissionReader {
  protected readonly logger = getLoggerFor(this);

  private readonly accountStore: AccountStore;
  private readonly aclStrategy: AuxiliaryIdentifierStrategy;

  public constructor(accountStore: AccountStore, aclStrategy: AuxiliaryIdentifierStrategy) {
    super();
    this.accountStore = accountStore;
    this.aclStrategy = aclStrategy;
  }

  public async handle(input: PermissionReaderInput): Promise<PermissionSet> {
    try {
      await this.ensurePodOwner(input);
    } catch (error: unknown) {
      this.logger.debug(`No pod owner Control permissions: ${createErrorMessage(error)}`);
      return {};
    }
    this.logger.debug(`Granting Control permissions to owner on ${input.identifier.path}`);

    return { [CredentialGroup.agent]: {
      read: true,
      write: true,
      append: true,
      create: true,
      delete: true,
      control: true,
    } as AclPermission };
  }

  /**
   * Verify that all conditions are fulfilled to give the owner access.
   */
  private async ensurePodOwner({ credentials, identifier }: PermissionReaderInput): Promise<void> {
    // We only check ownership when an ACL resource is targeted to reduce the number of storage calls
    if (!this.aclStrategy.isAuxiliaryIdentifier(identifier)) {
      throw new NotImplementedHttpError('Exception is only granted when accessing ACL resources');
    }
    if (!credentials.agent?.webId) {
      throw new NotImplementedHttpError('Only authenticated agents could be owners');
    }
    const accountId = await this.accountStore.findByWebId(credentials.agent.webId);
    if (!accountId) {
      throw new NotImplementedHttpError('No account registered for this WebID');
    }
    const account = await this.accountStore.find(accountId);
    if (!account) {
      this.logger.error(`Found invalid account ID ${accountId} through WebID ${credentials.agent.webId}`);
      throw new InternalServerError(`Invalid account ID ${accountId}`);
    }

    const pods = Object.keys(account.pods);
    if (!pods.some((pod): boolean => identifier.path.startsWith(pod))) {
      throw new NotImplementedHttpError('Not targeting a pod owned by this agent');
    }
  }
}
