export interface Storage {
  setItem: (key: string, val: any) => void,
  getItem: (key: string) => string | null,
  removeItem: (key: string) => void
}

export interface AuthStorage {
  retrieveLoginLocation: () => string|undefined,
  storeLoginLocation: (val: string) => void,
  removeLoginLocation: () => void,
  retrieveUserId: () => string|undefined,
  storeUserId: (val: string) => void,
  removeUserId: () => void,
  retrieveAccessToken: () => string|undefined,
  storeAccessToken: (val: string) => void,
  removeAccessToken: () => void,
  retrieveExpiresAt: () => number|undefined,
  storeExpiresAt: (val: number) => void,
  removeExpiresAt: () => void,
  retrieveNonce: () => number|undefined,
  storeNonce: (val: number) => void,
  removeNonce: () => void,
  retrieveState: () => any,
  storeState: (val: any) => void|undefined,
  removeState: () => any
}

export interface Keys {
  LOGIN_LOCATION: string,
  USER_ID: string
  ACCESS_TOKEN: string,
  EXPIRES_AT: string,
  NONCE: string,
  STATE: string,
}

export const defaultKeys = {
  LOGIN_LOCATION: 'login_location',
  USER_ID: 'user_id',
  ACCESS_TOKEN: 'access_token',
  EXPIRES_AT: 'expires_at',
  NONCE: 'auth_nonce',
  STATE: 'auth_state',
};

interface Args {
  storage?: Storage,
  keys?: Keys
}

const isNumber = (val: any): val is number => {
  return typeof val === 'number';
};

const stringOrUndefined = (val: string|null) => val ? val : undefined;

export function makeAuthStorage({ storage = localStorage, keys = defaultKeys }: Args): AuthStorage {
  const { LOGIN_LOCATION, USER_ID, ACCESS_TOKEN, EXPIRES_AT, NONCE, STATE } = keys;

  return {
    retrieveLoginLocation: () => stringOrUndefined(storage.getItem(LOGIN_LOCATION)),
    storeLoginLocation: loginLocation => storage.setItem(LOGIN_LOCATION, loginLocation),
    removeLoginLocation: () => storage.removeItem(LOGIN_LOCATION),
    retrieveUserId: () => stringOrUndefined(storage.getItem(USER_ID)),
    storeUserId: userId => storage.setItem(USER_ID, userId),
    removeUserId: () => storage.removeItem(USER_ID),
    retrieveAccessToken: () => stringOrUndefined(storage.getItem(ACCESS_TOKEN)),
    storeAccessToken: token => storage.setItem(ACCESS_TOKEN, token),
    removeAccessToken: () => storage.removeItem(ACCESS_TOKEN),
    retrieveNonce: () => {
      const val = storage.getItem(NONCE);
      return val ? Number.parseInt(val) : undefined;
    },
    retrieveExpiresAt: () => {
      const val = storage.getItem(EXPIRES_AT);
      return val ? Number.parseInt(val) : undefined;
    },
    storeExpiresAt: expiresAt => storage.setItem(EXPIRES_AT, expiresAt),
    removeExpiresAt: () => storage.removeItem(EXPIRES_AT),
    storeNonce: nonce => storage.setItem(NONCE, nonce),
    removeNonce: () => storage.removeItem(NONCE),
    retrieveState: () => stringOrUndefined(storage.getItem(STATE)),
    storeState: state => storage.setItem(STATE, state),
    removeState: () => storage.removeItem(STATE),
  };
}
