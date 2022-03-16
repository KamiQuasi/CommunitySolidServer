import assert from 'assert';
import { hash, compare } from 'bcrypt';
import { v4 } from 'uuid';
import type { ExpiringStorage } from '../../../../storage/keyvalue/ExpiringStorage';
import type { KeyValueStorage } from '../../../../storage/keyvalue/KeyValueStorage';
import type { PasswordStore } from './PasswordStore';

/**
 * A payload to persist a user account
 */
export interface LoginPayload {
  accountId: string;
  email: string;
  password: string;
  verified: boolean;
}

/**
 * A payload to persist the fact that a user
 * has requested to reset their password
 */
export interface ForgotPasswordPayload {
  email: string;
  recordId: string;
}

export type EmailPasswordData = LoginPayload | ForgotPasswordPayload;

// TODO:
export class BasePasswordStore implements PasswordStore {
  private readonly storage: KeyValueStorage<string, EmailPasswordData>;
  private readonly forgotPasswordStorage: ExpiringStorage<string, EmailPasswordData>;
  private readonly saltRounds: number;
  private readonly forgotPasswordExpiration: number;

  public constructor(storage: KeyValueStorage<string, EmailPasswordData>,
    forgotPasswordStorage: ExpiringStorage<string, EmailPasswordData>,
    saltRounds: number,
    forgotPasswordExpiration = 15) {
    this.storage = storage;
    this.forgotPasswordStorage = forgotPasswordStorage;
    this.forgotPasswordExpiration = forgotPasswordExpiration * 60 * 1000;
    this.saltRounds = saltRounds;
  }

  /**
   * Generates a ResourceIdentifier to store data for the given email.
   */
  private getEmailResourceIdentifier(email: string): string {
    return `email/${encodeURIComponent(email)}`;
  }

  /**
   * Generates a ResourceIdentifier to store data for the given recordId.
   */
  private getForgotPasswordRecordResourceIdentifier(recordId: string): string {
    return `forgot-password-resource-identifier/${encodeURIComponent(recordId)}`;
  }

  /* eslint-disable lines-between-class-members */
  /**
   * Helper function that converts the given e-mail to a resource identifier
   * and retrieves the login data from the internal storage.
   *
   * Will error if `checkExistence` is true and there is no login data for that email.
   */
  private async getLoginPayload(email: string, checkExistence: true):
  Promise<{ key: string; payload: LoginPayload }>;
  private async getLoginPayload(email: string, checkExistence: false):
  Promise<{ key: string; payload?: LoginPayload }>;
  private async getLoginPayload(email: string, checkExistence: boolean):
  Promise<{ key: string; payload?: LoginPayload }> {
    const key = this.getEmailResourceIdentifier(email);
    const account = await this.storage.get(key) as LoginPayload | undefined;
    assert(!checkExistence || account, 'Login does not exist');
    return { key, payload: account };
  }
  /* eslint-enable lines-between-class-members */

  public async authenticate(email: string, password: string): Promise<string> {
    const { payload } = await this.getLoginPayload(email, true);
    assert(payload.verified, 'Login still needs to be verified');
    assert(await compare(password, payload.password), 'Incorrect password');
    return payload.accountId;
  }

  public async create(email: string, accountId: string, password: string): Promise<void> {
    const { key, payload } = await this.getLoginPayload(email, false);
    assert(!payload, 'There already is a login for this email address');
    const newPayload: LoginPayload = {
      email,
      accountId,
      password: await hash(password, this.saltRounds),
      verified: false,
    };
    await this.storage.set(key, newPayload);
  }

  public async verify(email: string): Promise<void> {
    const { key, payload } = await this.getLoginPayload(email, true);
    payload.verified = true;
    await this.storage.set(key, payload);
  }

  public async changePassword(email: string, password: string): Promise<void> {
    const { key, payload } = await this.getLoginPayload(email, true);
    payload.password = await hash(password, this.saltRounds);
    await this.storage.set(key, payload);
  }

  public async delete(email: string): Promise<boolean> {
    const { key, payload } = await this.getLoginPayload(email, true);
    const exists = Boolean(payload);
    if (exists) {
      await this.storage.delete(key);
    }
    return exists;
  }

  public async generateForgotPasswordRecord(email: string): Promise<string> {
    const recordId = v4();
    await this.getLoginPayload(email, true);
    await this.forgotPasswordStorage.set(
      this.getForgotPasswordRecordResourceIdentifier(recordId),
      { recordId, email },
      this.forgotPasswordExpiration,
    );
    return recordId;
  }

  public async getForgotPasswordRecord(recordId: string): Promise<string | undefined> {
    const identifier = this.getForgotPasswordRecordResourceIdentifier(recordId);
    const forgotPasswordRecord = await this.forgotPasswordStorage.get(identifier) as ForgotPasswordPayload | undefined;
    return forgotPasswordRecord?.email;
  }

  public async deleteForgotPasswordRecord(recordId: string): Promise<void> {
    await this.forgotPasswordStorage.delete(this.getForgotPasswordRecordResourceIdentifier(recordId));
  }
}
