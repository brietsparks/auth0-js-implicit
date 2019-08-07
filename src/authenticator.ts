import { AuthorizeOptions, WebAuth } from 'auth0-js';

import { AuthStorage, Keys as StorageKeys, makeAuthStorage, Storage } from './storage';
import { noop, randomString } from './util';

export interface Options {
  storage?: Storage,
  storageKeys?: StorageKeys,
  reauthenticationLeeway?: number,
  onReauthenticationSuccess?: ReauthenticationSuccessHandler,
  onReauthenticationFailure?: ReauthenticationFailureHandler,
}

export type ReauthenticationSuccessHandler = (result: AuthResult) => void;
export type ReauthenticationFailureHandler = (error: Error) => void;

export interface AuthResponse {
  accessToken?: string;
  idTokenPayload?: any;
  expiresIn?: number;
}

export interface AuthResult {
  userId?: string,
  accessToken?: string,
  expiresAt?: number,
  redirectTo?: string,
}

export const DEFAULT_LEEWAY = 1200;

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

  getUserId() {
    return this.authStorage.retrieveUserId();
  }

  getAccessToken() {
    return this.authStorage.retrieveAccessToken();
  }

  getAuthStorage() {
    return this.authStorage;
  }

  promptLogin(currentLocation: string, opts: AuthorizeOptions = {}) {
    this.authStorage.storeLoginLocation(currentLocation);
    this.client.authorize({ ...opts, responseType });
  }

  handleLoginSuccess() {
    return new Promise<AuthResult>((resolve, reject) => {
      this.client.parseHash((error, parsed) => {
        if (parsed) {
          try {
            const { accessToken, userId, expiresAt } = extractAuthData(parsed);

            const redirectTo = this.authStorage.retrieveLoginLocation();
            this.authStorage.removeLoginLocation();
            this.authStorage.storeUserId(userId);
            this.authStorage.storeAccessToken(accessToken);
            this.authStorage.storeExpiresAt(expiresAt);

            this.setReauthenticationTimeout(expiresAt);

            resolve({ accessToken, userId, expiresAt, redirectTo });
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
    const state = randomString();

    return new Promise<AuthResult>(resolve => {
      const accessToken = authStorage.retrieveAccessToken();

      if (!accessToken) {
        if (currentLocation) {
          authStorage.storeLoginLocation(currentLocation);
          client.authorize({ responseType, state });
        }

        resolve({});
      }

      let expiresAt = authStorage.retrieveExpiresAt();

      const [isFresh, isExpiringSoon] = extractExpirationData(expiresAt, this.getReauthenticationLeeway());

      if (!isFresh && currentLocation) {
        authStorage.storeLoginLocation(currentLocation);
        authStorage.removeAccessToken();
        authStorage.removeExpiresAt();
        client.authorize({ responseType, state });
        resolve({});
      }

      if (isFresh && isExpiringSoon) {
        return this.reauthenticate()
          .then(({ userId, accessToken, expiresAt }) => {
            if (accessToken && expiresAt) {
              authStorage.storeAccessToken(accessToken);
              authStorage.storeExpiresAt(expiresAt);

              this.setReauthenticationTimeout(expiresAt);
              this.handleReauthenticationSuccess({ userId, accessToken, expiresAt });

              resolve({ accessToken, expiresAt });
            }
          })
          .catch(error => {
            authStorage.removeUserId();
            authStorage.removeAccessToken();
            authStorage.removeExpiresAt();

            this.handleReauthenticationFailure(error);

            resolve({});
          })
      }

      this.setReauthenticationTimeout(expiresAt as number);

      resolve({
        userId: authStorage.retrieveUserId(),
        accessToken,
        expiresAt
      });
    });
  }

  logout() {
    this.authStorage.removeUserId();
    this.authStorage.removeAccessToken();
    this.authStorage.removeExpiresAt();
    this.client.logout({ returnTo: this.logoutRedirectUrl });
  }

  private getReauthenticationLeeway() {
    const seconds = this.options.reauthenticationLeeway || DEFAULT_LEEWAY;
    return seconds * 1000;
  }

  private setReauthenticationTimeout(expiresAt: number) {
    window.clearTimeout(this.reauthTimeoutId);
    const timeout = (expiresAt - this.getReauthenticationLeeway()) - Date.now();
    this.reauthTimeoutId = window.setTimeout(this.authenticate.bind(this), timeout);
  }

  private handleReauthenticationSuccess(result: AuthResult) {
    const handleSuccess = this.options.onReauthenticationSuccess || noop;
    handleSuccess(result);
  }

  private handleReauthenticationFailure(error: Error) {
    const handleFailure = this.options.onReauthenticationFailure || noop;
    handleFailure(error);
  }

  private reauthenticate() {
    return new Promise<AuthResult>((resolve, reject) => {
      const opts = { responseType };

      this.client.checkSession(opts, (error, result) => {
        if (error) {
          reject(error);
        }

        try {
          const { userId, accessToken, expiresAt } = extractAuthData(result);
          resolve({ userId, accessToken, expiresAt });
        } catch (error) {
          this.handleReauthenticationFailure(error)
        }
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

  if (!expiresIn || typeof expiresIn !== 'number' || !(expiresIn > -1)) {
    throw new Error(`expected expiresIn to be a positive integer, got ${expiresIn}`);
  }

  let sub = idTokenPayload.sub;

  if (!sub) {
    throw new Error('idTokenPayload.sub not found in parsed hash');
  }

  const expiresAt = Date.now() + (expiresIn * 1000);

  return { userId: sub, accessToken, expiresAt };
}

export function extractExpirationData(expiresAt?: number, leeway?: number): [boolean, boolean?] {
  if (!expiresAt) {
    return [false]
  }

  const expiresWithin = expiresAt - Date.now();

  if (isNaN(expiresWithin) || expiresWithin < 0) {
    return [false]
  }

  const isExpiringSoon = leeway && Number.isInteger(leeway) ? expiresWithin < leeway : true;

  return [true, isExpiringSoon];
}
