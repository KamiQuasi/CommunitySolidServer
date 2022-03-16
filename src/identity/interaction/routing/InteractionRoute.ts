// TODO: find good place for these
// TODO: also create type versions? e.g. PATH_ACCOUNT_ID_TYPE
// TODO: PATH_EMAIL_LINK etc.
// TODO: could instead work with extra function on IdInteractionRoute that returns the ID name?
//       ^ does not work if multiple ids need to be entered (both account and pod for example)
export type PathAccountId = 'accountId';
export type PathCredentialsId = 'credentialsId';
export type PathPasswordId = 'passwordId';
export type PathPodId = 'podId';
export type PathWebIdHash = 'webIdHash';

// TODO: move somewhere where relevant for each case
export type AccountRoute = InteractionRoute<PathAccountId>;
export type AccountCredentialsRoute = InteractionRoute<PathCredentialsId | PathAccountId>;
export type AccountPasswordRoute = InteractionRoute<PathPasswordId | PathAccountId>;
export type AccountPodRoute = InteractionRoute<PathPodId | PathAccountId>;
export type AccountWebIdRoute = InteractionRoute<PathWebIdHash | PathAccountId>;

// TODO: all tsdocs below
/**
 * Stores the path that can be used for an API call.
 * This can also be a path pattern that matches multiple paths
 */
export interface InteractionRoute<T extends string = never> {
  /**
   * A string representation of the path.
   * @param accountId - The ID of the currently active user, if there is one.
   * @returns The stored path, or undefined if the path depends on the `accountId` and none was provided
   *          or there is no single representation.
   */
  getPath: (parameters: Record<T, string | undefined>) => string | undefined;

  /**
   * Checks if the provided path matches the route (pattern).
   * @param path - The path to verify.
   * @param accountId - The ID of the currently active user, if there is one.
   */
  matchPath: (path: string) => Record<T, string> | undefined;
}
