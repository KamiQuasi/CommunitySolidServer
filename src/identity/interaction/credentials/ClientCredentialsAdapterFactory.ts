import type { AdapterPayload, Adapter } from 'oidc-provider';
import type { KeyValueStorage } from '../../../storage/keyvalue/KeyValueStorage';
import type { AccountStore } from '../../account/AccountStore';
import type { AdapterFactory } from '../../storage/AdapterFactory';
import { PassthroughAdapterFactory, PassthroughAdapter } from '../../storage/PassthroughAdapterFactory';

export interface ClientCredentials {
  accountId: string;
  secret: string;
  webId: string;
}

/**
 * A {@link PassthroughAdapter} that overrides the `find` function
 * by checking if there are stored client credentials for the given ID
 * if no payload is found in the source.
 */
export class ClientCredentialsAdapter extends PassthroughAdapter {
  private readonly accountStore: AccountStore;
  private readonly storage: KeyValueStorage<string, ClientCredentials>;

  public constructor(name: string, source: Adapter, accountStore: AccountStore, storage: KeyValueStorage<string, ClientCredentials>) {
    super(name, source);
    this.accountStore = accountStore;
    this.storage = storage;
  }

  public async find(id: string): Promise<AdapterPayload | void | undefined> {
    let payload = await this.source.find(id);

    if (!payload && this.name === 'Client') {
      const credentials = await this.storage.get(id);
      if (credentials) {
        // Make sure the WebID is still linked to the to the account.
        // Unlinking a WebID does not necessarily delete the corresponding credential tokens.
        const account = await this.accountStore.find(credentials.accountId);
        if (!account || !account.webIds[credentials.webId]) {
          await this.storage.delete(id);
          return;
        }

        /* eslint-disable @typescript-eslint/naming-convention */
        payload = {
          client_id: id,
          client_secret: credentials.secret,
          grant_types: [ 'client_credentials' ],
          redirect_uris: [],
          response_types: [],
        };
        /* eslint-enable @typescript-eslint/naming-convention */
      }
    }
    return payload;
  }
}

export class ClientCredentialsAdapterFactory extends PassthroughAdapterFactory {
  private readonly accountStore: AccountStore;
  private readonly storage: KeyValueStorage<string, ClientCredentials>;

  public constructor(source: AdapterFactory, accountStore: AccountStore, storage: KeyValueStorage<string, ClientCredentials>) {
    super(source);
    this.accountStore = accountStore;
    this.storage = storage;
  }

  public createStorageAdapter(name: string): Adapter {
    return new ClientCredentialsAdapter(name, this.source.createStorageAdapter(name), this.accountStore, this.storage);
  }
}
