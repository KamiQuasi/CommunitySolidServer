import { BadRequestHttpError } from '../../util/errors/BadRequestHttpError';
import type { Account } from './Account';
import type { AccountStore } from './AccountStore';

// TODO: merge with interactionUtil?

// TODO: can this instead throw a redirect pointing to the login page?
export async function getRequiredAccount(accountStore: AccountStore, accountId?: string): Promise<Account> {
  const account = accountId && await accountStore.find(accountId);
  if (!account) {
    throw new BadRequestHttpError('This action can only be performed when a user is logged in.');
  }
  return account;
}
