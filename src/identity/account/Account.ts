// TODO:
export type Account = {
  id: string;
  logins: Record<string, string>;
  pods: Record<string, string>;
  webIds: Record<string, string>;
  credentials: Record<string, string>;
};
