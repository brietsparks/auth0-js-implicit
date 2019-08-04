import { AuthStorage, Keys as StorageKeys, makeAuthStorage, Storage } from './storage';
import { AuthorizeOptions, WebAuth } from 'auth0-js';

export interface Options {
  threshold?: number,
  interval?: number,
  storage?: Storage,
  storageKeys?: StorageKeys,
}

export interface AuthResponse {
  accessToken?: string;
  idTokenPayload?: any;
  expiresIn?: number;
}

export interface AuthData {
  userId: string,
  accessToken: string,
  expiresAt: number
}

export const DEFAULT_THRESHOLD = 1200;
export const DEFAULT_INTERVAL = 600;

export const responseType = 'token id_token';

export class Authenticator {
  client: WebAuth;
  authStorage: AuthStorage;
  logoutRedirectUrl: string;
  options: Options;
  reauthTimeoutId?: number;

  constructor(client: WebAuth, logoutRedirectUrl: string, options: Options = {}) {
    this.client = client;
    this.logoutRedirectUrl = logoutRedirectUrl;
    this.options = options;

    this.authStorage = makeAuthStorage({
      storage: options.storage,
      keys: options.storageKeys
    });
  }

  promptLogin(currentLocation: string, opts: AuthorizeOptions = {}) {
    this.authStorage.storeLoginLocation(currentLocation);
    this.client.authorize({ ...opts, responseType });
  }

  handleLoginSuccess() {
    return new Promise<AuthData>((resolve, reject) => {
      this.client.parseHash((error, parsed) => {
        if (parsed) {
          try {
            const { accessToken, userId, expiresAt } = extractAuthData(parsed);

            this.authStorage.removeLoginLocation();
            this.authStorage.storeToken(accessToken);
            this.authStorage.storeExpiresAt(expiresAt.toString());

            resolve({ accessToken, userId, expiresAt });
          } catch (error) {
            reject(error)
          }
        } else if (error) {
          reject(error)
        } else {
          reject(new Error('parseHash neither parsed the hash successfully nor returned an error'));
        }
      });
    })
  }

  authenticate(currentLocation?: string) {
    const authStorage = this.authStorage;
    const client = this.client;
    const options = this.options;

    const accessToken = authStorage.retrieveAccessToken();

    if (!accessToken) {
      if (currentLocation) {
        authStorage.storeLoginLocation(currentLocation);
        client.authorize({ responseType });
      }

      return;
    }

    const expiresAt = authStorage.retrieveExpiresAt();

    const [isValid, isExpiringSoon] = extractExpirationData(expiresAt, options.threshold);

    if (!isValid && currentLocation) {
      authStorage.storeLoginLocation(currentLocation);
      authStorage.removeToken();
      authStorage.removeExpiresAt();
      client.authorize({ responseType });
      return;
    }

    if (isValid && isExpiringSoon) {
      return this.reauthenticate().then(({ accessToken, expiresAt }) => {
        authStorage.storeToken(accessToken);
        authStorage.storeExpiresAt(expiresAt.toString());
        this.reauthTimeoutId = window.setTimeout(() => this.authenticate(), options.interval);
      });
    }

    this.reauthTimeoutId = window.setTimeout(() => this.authenticate(), options.interval);
  }

  logout() {
    this.authStorage.removeToken();
    this.client.logout({
      returnTo: this.logoutRedirectUrl
      // clientID needed?
    })
  }

  private reauthenticate() {
    return new Promise<AuthData>((resolve, reject) => {
      this.client.checkSession({}, (error, result) => {
        if (error) {
          reject(error);
        }

        const { userId, accessToken, expiresAt } = extractAuthData(result);

        resolve({ userId, accessToken, expiresAt });
      });
    })
  }
}

export function extractAuthData(parsed: AuthResponse) {
  let { idTokenPayload, accessToken, expiresIn } = parsed;

  if (typeof idTokenPayload !== 'object') {
    throw new Error(`expected idTokenPayload to be an object, got ${idTokenPayload}`);
  }

  if (typeof accessToken !== 'string') {
    throw new Error(`expected accessToken to be a string, got ${accessToken}`);
  }

  if (!expiresIn || !Number.isInteger(expiresIn) || !(expiresIn > -1)) {
    throw new Error(`expected expiresIn to be a positive integer, got ${expiresIn}`);
  }

  let sub = idTokenPayload.sub;

  if (!sub) {
    throw new Error('idTokenPayload.sub not found in parsed hash');
  }

  const expiresAt = Date.now() + (expiresIn * 1000);

  return { userId: sub, accessToken, expiresAt };
}

export function extractExpirationData(expiresAtString: string|null, threshold: number = DEFAULT_THRESHOLD): [boolean, boolean?] {
  if (expiresAtString === null) {
    return [false]
  }

  const expiresAt = +expiresAtString;

  const expiresWithin = expiresAt - Date.now();

  if (isNaN(expiresWithin) || expiresWithin < 0) {
    return [false]
  }

  const isExpiringSoon = Number.isInteger(threshold) ? expiresWithin < threshold : true;

  return [true, isExpiringSoon];
}
