import { AuthorizeOptions, WebAuth } from 'auth0-js';

import {
  Authenticator, extractAuthData, extractExpirationData, DEFAULT_LEEWAY,
  responseType, ReauthenticationSuccessHandler, ReauthenticationFailureHandler
} from './authenticator';
import { makeClient } from './test-utils/client';
import MemStorage from './test-utils/mem-storage';
import { AuthStorage, Storage } from './storage';

const tsToSeconds = (n: number) => Math.trunc(n / 1000);

describe('authenticator', () => {
  const mockExpiresInSeconds = 7200;
  const mockExpiresInMs = mockExpiresInSeconds * 1000;
  const leewaySeconds = DEFAULT_LEEWAY;
  const leewayMs = leewaySeconds * 1000;

  describe('Authenticator', () => {
    let client: WebAuth,
      storage: Storage,
      auth: Authenticator,
      authStorage: AuthStorage,
      onReauthenticationSuccess: jest.MockedFunction<ReauthenticationSuccessHandler>,
      onReauthenticationFailure: jest.MockedFunction<ReauthenticationFailureHandler>
    ;

    beforeEach(() => {
      client = makeClient();
      storage = new MemStorage();
      onReauthenticationSuccess = jest.fn();
      onReauthenticationFailure = jest.fn();
      auth = new Authenticator(client, '/logout', {
        storage,
        onReauthenticationSuccess,
        onReauthenticationFailure
      });
      authStorage = auth.authStorage;
    });

    test('promptLogin', () => {
      client.authorize = jest.fn();
      auth.promptLogin('/page');

      expect(authStorage.retrieveLoginLocation()).toEqual('/page');
      expect(client.authorize).toBeCalledWith({ responseType });

      auth.promptLogin('/page-1', { prompt: 'none' });
      expect(authStorage.retrieveLoginLocation()).toEqual('/page-1');
      expect(client.authorize).toBeCalledWith({ responseType, prompt: 'none' });
    });

    describe('handleLoginSuccess', () => {
      test('with response data', async () => {
        client.parseHash = jest.fn().mockImplementation(cb => cb(undefined, {
          accessToken: 't',
          idTokenPayload: { sub: 'u' },
          expiresIn: mockExpiresInSeconds
        }));

        const expectedExpiresAt = Date.now() + mockExpiresInMs;

        const { accessToken, userId, expiresAt } = await auth.handleLoginSuccess();

        expect(accessToken).toEqual('t');
        expect(userId).toEqual('u');
        expect(tsToSeconds(expiresAt as number)).toEqual(tsToSeconds(expectedExpiresAt));

        expect(authStorage.retrieveAccessToken()).toEqual('t');
        expect(authStorage.retrieveUserId()).toEqual('u');
        expect(tsToSeconds(authStorage.retrieveExpiresAt() as number)).toEqual(tsToSeconds(expectedExpiresAt));
      });

      test('with error', async () => {
        client.parseHash = jest.fn().mockImplementation(cb => cb(new Error('error!'), undefined));

        try {
          await auth.handleLoginSuccess();
        } catch (error) {
          expect(error.message).toEqual('error!');
          expect(authStorage.retrieveAccessToken()).toEqual(undefined);
          expect(authStorage.retrieveUserId()).toEqual(undefined);
          expect(authStorage.retrieveExpiresAt()).toEqual(undefined);
        }
      });

      test('with neither response nor error', async () => {
        client.parseHash = jest.fn().mockImplementation(cb => cb(undefined, undefined));

        try {
          await auth.handleLoginSuccess()
        } catch (error) {
          expect(error.message).toEqual('parseHash neither parsed the hash successfully nor returned an error');
        }
      });
    });

    describe('authenticate', () => {
      test('no access token, auth required', async () => {
        client.authorize = jest.fn();

        const result = await auth.authenticate('/page');

        expect(authStorage.retrieveLoginLocation()).toEqual('/page');

        expect(result).toEqual({});

        // @ts-ignore
        const authorizeArgs = client.authorize.mock.calls[0][0];
        expect(authorizeArgs.responseType).toEqual(responseType);
      });

      test('no access token, auth not required', async () => {
        client.authorize = jest.fn();

        const result = await auth.authenticate();

        expect(authStorage.retrieveLoginLocation()).toEqual(undefined);

        expect(client.authorize).not.toHaveBeenCalled();
        expect(result).toEqual({});
      });

      test('auth required, access token expired', async () => {
        authStorage.storeAccessToken('t');
        authStorage.storeExpiresAt(0);

        client.authorize = jest.fn();

        await auth.authenticate('/page');

        expect(authStorage.retrieveLoginLocation()).toEqual('/page');
        expect(authStorage.retrieveAccessToken()).toEqual(undefined);
        expect(authStorage.retrieveExpiresAt()).toEqual(undefined);

        // @ts-ignore
        const authorizeArgs = client.authorize.mock.calls[0][0];
        expect(authorizeArgs.responseType).toEqual(responseType);
      });

      test('access token fresh and not expiring soon', async () => {
        const expectedExpiresAt = (Date.now() + 10000 * 1000);
        authStorage.storeExpiresAt(expectedExpiresAt);
        authStorage.storeUserId('u');
        authStorage.storeAccessToken('t');

        client.authorize = jest.fn();

        const { userId, accessToken, expiresAt } = await auth.authenticate();

        expect(userId).toEqual('u');
        expect(accessToken).toEqual('t');
        expect(expiresAt).toEqual(expectedExpiresAt);
      });

      describe('silent reauthentication', () => {
        test('access token fresh but within reauthentication threshold', async () => {
          // token 't' expires in 2 seconds
          authStorage.storeAccessToken('t');
          authStorage.storeExpiresAt((Date.now() + 2000));

          client.checkSession = jest.fn().mockImplementation((opts, cb) => cb(undefined, {
            accessToken: 't1',
            idTokenPayload: { sub: 'u' },
            expiresIn: mockExpiresInSeconds
          }));
          jest.spyOn(auth, 'authenticate');
          jest.useFakeTimers();

          const expectedExpiresAt = Date.now() + mockExpiresInMs;

          await auth.authenticate();

          // the new auth result was stored
          expect(authStorage.retrieveAccessToken()).toEqual('t1');
          expect(tsToSeconds((authStorage.retrieveExpiresAt() as number))).toEqual(tsToSeconds(expectedExpiresAt));

          // the new auth result was passed to the reauthentication handler
          const { userId, accessToken, expiresAt } = onReauthenticationSuccess.mock.calls[0][0];
          expect(userId).toEqual('u');
          expect(accessToken).toEqual('t1');
          expect(tsToSeconds(expiresAt as number)).toEqual(tsToSeconds(expectedExpiresAt));


          // authenticate is called again at the next reauthentication threshold
          jest.advanceTimersByTime(mockExpiresInMs - leewayMs - 1000);
          expect(auth.authenticate).toHaveBeenCalledTimes(1);
          jest.advanceTimersByTime(2000);
          expect(auth.authenticate).toHaveBeenCalledTimes(2);
        });

        test('access token fresh and not within reauthentication threshold', async () => {
          const expectedExpiresAt = Date.now() + mockExpiresInMs;
          authStorage.storeAccessToken('t');
          authStorage.storeExpiresAt(expectedExpiresAt);

          client.authorize = jest.fn();
          jest.spyOn(auth, 'authenticate');
          jest.useFakeTimers();

          const thresholdTimeout = expectedExpiresAt - leewayMs - Date.now();

          await auth.authenticate();

          jest.advanceTimersByTime(thresholdTimeout - 1000);
          expect(auth.authenticate).toHaveBeenCalledTimes(1);

          jest.advanceTimersByTime(2000);
          expect(auth.authenticate).toHaveBeenCalledTimes(2);
        });
      });
    });

    test('logout', () => {
      authStorage.storeAccessToken('t');
      client.logout = jest.fn();

      auth.logout();

      expect(authStorage.retrieveAccessToken()).toEqual(undefined);
      expect(client.logout).toBeCalledWith({ returnTo: '/logout' });
    });
  });

  describe('extractAuthData', () => {
    test('with valid data', () => {
      const parsed = {
        accessToken: 't',
        idTokenPayload: { sub: 'u' },
        expiresIn: mockExpiresInSeconds
      };

      const expectedExpiresAt = Date.now() + (parsed.expiresIn * 1000);

      let actual, expected;

      actual = extractAuthData(parsed);

      expected = {
        accessToken: 't',
        userId: 'u',
        expiresAt: expectedExpiresAt
      };
      expect(actual).toEqual(expected);
    });

    describe('with invalid data', () => {
      const authResponse = {
        idTokenPayload: { sub: 'u' },
        accessToken: 't',
        expiresIn: mockExpiresInSeconds,
      };

      test('invalid idTokenPayload', () => {
        // @ts-ignore
        const actual = () => extractAuthData({...authResponse, idTokenPayload: 5 });
        const error = new Error('expected idTokenPayload to be an object, got 5');
        expect(actual).toThrow(error);
      });

      test('invalid accessToken', () => {
        // @ts-ignore
        const actual = () => extractAuthData({...authResponse, accessToken: 5 });
        const error = new Error('expected accessToken to be a string, got 5');
        expect(actual).toThrow(error);
      });

      test('undefined expiresIn', () => {
        // @ts-ignore
        const actual = () => extractAuthData({...authResponse, expiresIn: undefined });
        const error = new Error('expected expiresIn to be a positive integer, got undefined');
        expect(actual).toThrow(error);
      });

      test('non-integer expiresIn', () => {
        // @ts-ignore
        const actual = () => extractAuthData({...authResponse, expiresIn: 's' });
        const error = new Error('expected expiresIn to be a positive integer, got s');
        expect(actual).toThrow(error);
      });

      test('negative expiresIn', () => {
        const actual = () => extractAuthData({...authResponse, expiresIn: -5 });
        const error = new Error('expected expiresIn to be a positive integer, got -5');
        expect(actual).toThrow(error);
      });

      test('sub', () => {
        const actual = () => extractAuthData({...authResponse, idTokenPayload: {} });
        const error = new Error('idTokenPayload.sub not found in parsed hash');
        expect(actual).toThrow(error);
      });
    });
  });

  describe('extractExpirationData', () => {
    describe('valid data', () => {
      test('undefined expiresAt', () => {
        const actual = extractExpirationData(undefined, mockExpiresInSeconds);
        const expected = [false];
        expect(actual).toEqual(expected);
      });

      test('expiresAt is in the past', () => {
        const expiresAt = (Date.now() - 10000);
        const actual = extractExpirationData(expiresAt, mockExpiresInSeconds);
        const expected = [false];
        expect(actual).toEqual(expected);
      });

      test('not expired, expiring within leeway', () => {
        const expiresAt = (Date.now() + 5000);
        const actual = extractExpirationData(expiresAt, mockExpiresInSeconds);
        const expected = [true, true];
        expect(actual).toEqual(expected);
      });

      test('not expired, not expiring within leeway', () => {
        const expiresAt = (Date.now() + 9000);
        const actual = extractExpirationData(expiresAt, mockExpiresInSeconds);
        const expected = [true, false];
        expect(actual).toEqual(expected);
      });
    });

    describe('invalid data', () => {
      test('invalid expiresAt', () => {
        [{}, [], 's', function() {}].forEach(invalidExpiresAt => {
          // @ts-ignore
          const actual = extractExpirationData(invalidExpiresAt, mockExpiresInSeconds);
          const expected = [false];
          expect(actual).toEqual(expected);
        })
      });

      test('invalid leeway', () => {
        [{}, [], 's', function() {}].forEach(invalidLeeway => {
          const expiresAt = (Date.now() + 5000).toString();
          // @ts-ignore
          const actual = extractExpirationData(expiresAt, invalidLeeway);
          const expected = [true, true];
          expect(actual).toEqual(expected);
        })
      });
    });
  });
});
