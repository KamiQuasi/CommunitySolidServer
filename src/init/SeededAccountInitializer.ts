import { readJson } from 'fs-extra';
import { RepresentationMetadata } from '../http/representation/RepresentationMetadata';
import type { JsonInteractionHandler } from '../identity/interaction/JsonInteractionHandler';
import { getLoggerFor } from '../logging/LogUtil';
import { Initializer } from './Initializer';

// TODO: typings are lost here unfortunately

// TODO: document that this was changed as well

// TODO:
/**
 * Uses a {@link RegistrationManager} to initialize accounts and pods
 * for all seeded pods. Reads the pod settings from seededPodConfigJson.
 */
export class SeededAccountInitializer extends Initializer {
  protected readonly logger = getLoggerFor(this);

  private readonly registrationHandler: JsonInteractionHandler;
  private readonly configFilePath: string | null;

  public constructor(registrationHandler: JsonInteractionHandler, configFilePath: string | null) {
    super();
    this.registrationHandler = registrationHandler;
    this.configFilePath = configFilePath;
  }

  public async handle(): Promise<void> {
    if (!this.configFilePath) {
      return;
    }
    const configuration = await readJson(this.configFilePath, 'utf8');

    let count = 0;
    for await (const input of configuration) {
      const json = {
        account: {},
        ...input,
      };

      // This depends on the configured handlers, but we need some way to identify the user in the logs.
      // Could be changed in the future if we add fields to the account request.
      const name = json.login.email;

      this.logger.info(`Initializing account ${name}`);

      // TODO: shouldn't need all these fields
      // Simulate a POST request with the valid fields
      const target = { path: '' };
      const metadata = new RepresentationMetadata(target);
      const result = await this.registrationHandler.handleSafe({ method: 'POST', target, metadata, json });
      const errorKey = Object.keys(result.json).find((key): boolean => Boolean((result.json[key] as any).error));
      if (errorKey) {
        const { error } = result.json[errorKey] as any;
        this.logger.warn(`Error while processing ${name} on step ${errorKey}: ${error}`);
      } else {
        this.logger.info(`Initialized seeded pod and account for "${name}".`);
      }

      count += 1;
    }
    this.logger.info(`Initialized ${count} seeded pods.`);
  }
}
