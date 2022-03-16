import { v4 } from 'uuid';
import type { ExpiringStorage } from '../../storage/keyvalue/ExpiringStorage';
import { BadRequestHttpError } from '../../util/errors/BadRequestHttpError';
import { NotFoundHttpError } from '../../util/errors/NotFoundHttpError';
import { NotImplementedHttpError } from '../../util/errors/NotImplementedHttpError';
import type { Account } from './Account';
import type { AccountStore } from './AccountStore';

// TODO: cookie ttl in minutes
export class BaseAccountStore implements AccountStore {
  private readonly storage: ExpiringStorage<string, any>;
  private readonly cookieTtl: number;

  public constructor(storage: ExpiringStorage<string, any>, cookieTtl = 20160) {
    this.storage = storage;
    this.cookieTtl = cookieTtl * 60 * 1000;
  }

  public async create(): Promise<Account> {
    const id = v4();
    const account: Account = {
      id,
      logins: {},
      pods: {},
      webIds: {},
      credentials: {},
    };

    await this.storage.set(id, account, 24 * 60 * 60 * 1000);
    return account;
  }

  public async find(id: string): Promise<Account | undefined> {
    return this.storage.get(id);
  }

  public async update(account: Account): Promise<void> {
    const oldAccount = await this.find(account.id);
    // Make sure the account exists
    if (!oldAccount) {
      throw new NotFoundHttpError();
    }

    if (Object.keys(account.logins).length <= 0) {
      throw new BadRequestHttpError('An account needs at least 1 login method.');
    }

    await this.storage.set(account.id, account);

    // TODO: this could also use its own storage, similar to how credentials and logins do it
    // Update WebID links for `findByWebId` call below
    // TODO: !!! need to prevent registering a WebID already registered with a different account !!!
    for (const webId of new Set<string>([ ...Object.keys(oldAccount.webIds), ...Object.keys(account.webIds) ])) {
      if (!account.webIds[webId]) {
        await this.storage.delete(webId);
      } else if (!oldAccount.webIds[webId]) {
        await this.storage.set(webId, account.id);
      }
    }
  }

  public async delete(): Promise<void> {
    // We would also have to delete associated WebIds/Pods/Login settings
    throw new NotImplementedHttpError('Delete not supported yet.');
  }

  // TODO: this is only needed for ownership check? Could instead store podBaseUrl -> WebID links
  //       ^ probably future work
  public async findByWebId(webId: string): Promise<string | undefined> {
    return await this.storage.get(webId);
  }

  public async findByCookie(cookie: string): Promise<string | undefined> {
    const accountId = await this.storage.get(cookie);
    if (accountId) {
      // Reset cookie expiration
      await this.storage.set(cookie, accountId, this.cookieTtl);
    }
    return accountId;
  }

  public async generateCookie(accountId: string): Promise<string> {
    // TODO: sign cookie?
    const cookie = v4();
    await this.storage.set(cookie, accountId, this.cookieTtl);
    return cookie;
  }

  public async deleteCookie(cookie: string): Promise<boolean> {
    return await this.storage.delete(cookie);
  }
}
