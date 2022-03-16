export interface PasswordStore {
  /**
   * Authenticate if the email and password are correct and return the Account ID if it is.
   * Throw an error if it is not.
   * @param email - The user's email.
   * @param password - This user's password.
   * @returns The user's Account ID.
   */
  authenticate: (email: string, password: string) => Promise<string>;

  /**
   * Stores a new login entry for this account.
   * @param email - Account email.
   * @param accountId - Account ID.
   * @param password - Account password.
   */
  create: (email: string, accountId: string, password: string) => Promise<void>;

  /**
   * Verifies the login creation. This can be used with, for example, email verification.
   * The login can only be used after it is verified.
   * In case verification is not required, this should be called immediately after the `create` call.
   * @param email - The account email.
   */
  verify: (email: string) => Promise<void>;

  /**
   * Changes the password.
   * @param email - The user's email.
   * @param password - The user's password.
   */
  changePassword: (email: string, password: string) => Promise<void>;

  /**
   * Delete the login entry of this email address.
   * @param email - The user's email.
   */
  delete: (email: string) => Promise<boolean>;

  /**
   * Creates a Forgot Password Confirmation Record. This will be to remember that
   * a user has made a request to reset a password. Throws an error if the email doesn't
   * exist
   * @param email - The user's email.
   * @returns The record id. This should be included in the reset password link.
   */
  generateForgotPasswordRecord: (email: string) => Promise<string>;

  /**
   * Gets the email associated with the forgot password confirmation record or undefined
   * if it's not present
   * @param recordId - The record id retrieved from the link.
   * @returns The user's email.
   */
  getForgotPasswordRecord: (recordId: string) => Promise<string | undefined>;

  /**
   * Deletes the Forgot Password Confirmation Record
   * @param recordId - The record id of the forgot password confirmation record.
   */
  deleteForgotPasswordRecord: (recordId: string) => Promise<void>;
}
