export interface Storage {
  setItem: (key: string, val: any) => void,
  getItem: (key: string) => string | null,
  removeItem: (key: string) => void
}

export type Retrieve = () => string | null;
export type Store = (val: string) => void;
export type Remove = () => void;

export interface AuthStorage {
  retrieveLoginLocation: Retrieve,
  storeLoginLocation: Store,
  removeLoginLocation: Remove,
  retrieveAccessToken: Retrieve,
  storeAccessToken: Store,
  removeAccessToken: Remove,
  retrieveExpiresAt: Retrieve,
  storeExpiresAt: Store,
  removeExpiresAt: Remove,
  retrieveNonce: Retrieve,
  storeNonce: Store,
  removeNonce: Remove,
  retrieveState: Retrieve
  storeState: Store,
  removeState: Remove
}

export interface Keys {
  LOGIN_LOCATION: string,
  ACCESS_TOKEN: string,
  EXPIRES_AT: string,
  NONCE: string,
  STATE: string,
}

export const defaultKeys = {
  LOGIN_LOCATION: 'login_location',
  ACCESS_TOKEN: 'access_token',
  EXPIRES_AT: 'expires_at',
  NONCE: 'auth_nonce',
  STATE: 'auth_state',
};

interface Args {
  storage?: Storage,
  keys?: Keys
}

export function makeAuthStorage({ storage = localStorage, keys = defaultKeys }: Args): AuthStorage {
  const { LOGIN_LOCATION, ACCESS_TOKEN, EXPIRES_AT, NONCE, STATE } = keys;

  return {
    retrieveLoginLocation: () => storage.getItem(LOGIN_LOCATION),
    storeLoginLocation: (loginLocation: string) => storage.setItem(LOGIN_LOCATION, loginLocation),
    removeLoginLocation: () => storage.removeItem(LOGIN_LOCATION),
    retrieveAccessToken: () => storage.getItem(ACCESS_TOKEN),
    storeAccessToken: (token: string) => storage.setItem(ACCESS_TOKEN, token),
    removeAccessToken: () => storage.removeItem(ACCESS_TOKEN),
    retrieveNonce: () => storage.getItem(NONCE),
    retrieveExpiresAt: () => storage.getItem(EXPIRES_AT),
    storeExpiresAt: (expiresAt: string) => storage.setItem(EXPIRES_AT, expiresAt),
    removeExpiresAt: () => storage.removeItem(EXPIRES_AT),
    storeNonce: (nonce: string) => storage.setItem(NONCE, nonce),
    removeNonce: () => storage.removeItem(NONCE),
    retrieveState: () => storage.getItem(STATE),
    storeState: (state: string) => storage.setItem(STATE, state),
    removeState: () => storage.removeItem(STATE),
  };
}
