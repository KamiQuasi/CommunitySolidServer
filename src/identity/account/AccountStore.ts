import type { Account } from './Account';

// TODO:
export interface AccountStore {
  create: () => Promise<Account>;
  delete: (accountId: string) => Promise<void>;
  find: (id: string) => Promise<Account | undefined>;
  update: (account: Account) => Promise<void>;
  findByWebId: (webId: string) => Promise<string | undefined>;
  findByCookie: (cookie: string) => Promise<string | undefined>;
  generateCookie: (accountId: string) => Promise<string>;
  deleteCookie: (cookie: string) => Promise<boolean>;
}
