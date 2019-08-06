import { Authenticator, extractAuthData, extractExpirationData, responseType } from './authenticator';
import { makeClient } from './test-utils/client';
import MemStorage from './test-utils/mem-storage';
import { WebAuth } from 'auth0-js';
import { AuthStorage, Storage } from './storage';

const tsToSeconds = (n: number) => Math.trunc(n / 1000);

describe('authenticator', () => {
  describe('Authenticator', () => {
    let client: WebAuth,
      storage: Storage,
      auth: Authenticator,
      authStorage: AuthStorage
    ;

    beforeEach(() => {
      client = makeClient();
      storage = new MemStorage();
      auth = new Authenticator(client, '/logout', { storage });
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
          expiresIn: 7200
        }));

        const expectedExpiresAt = Date.now() + (7200 * 1000);

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
        expect(client.authorize).toBeCalledWith({ responseType });
        expect(result).toEqual({});
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
        expect(client.authorize).toBeCalledWith({ responseType });
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
        // test('access token fresh but expiring soon', () => {
        //   authStorage.storeAccessToken('t');
        //   authStorage.storeExpiresAt((Date.now() + 2000));
        //
        //   client.checkSession = jest.fn().mockImplementation((opts, cb) => cb(undefined, {
        //     accessToken: 't1',
        //     idTokenPayload: { sub: 'u' },
        //     expiresIn: 7200
        //   }));
        //   jest.spyOn(auth, 'authenticate');
        //   jest.useFakeTimers();
        //
        //   auth.authenticate().then(({ userId }) => {
        //     jest.runOnlyPendingTimers();
        //     expect(auth.authenticate).toHaveBeenCalledTimes(23);
        //   });
        // });

        // test('access token fresh and not expiring soon', async () => {
        //   authStorage.storeAccessToken('t');
        //   authStorage.storeExpiresAt((Date.now() + 10000 * 1000));
        //
        //   client.authorize = jest.fn();
        //   jest.spyOn(auth, 'authenticate');
        //   // jest.useFakeTimers();
        //
        //   const r = auth.authenticate();
        //
        //   await r;
        //     // .then(() => {
        //     //   expect(1).toEqual(2);
        //     // });
        //
        //   // jest.runOnlyPendingTimers();
        //
        //   // expect(auth.authenticate).toHaveBeenCalledTimes(2);
        // });
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
        expiresIn: 7200
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
        expiresIn: 7200,
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
        const actual = extractExpirationData(undefined, 7200);
        const expected = [false];
        expect(actual).toEqual(expected);
      });

      test('expiresAt is in the past', () => {
        const expiresAt = (Date.now() - 10000);
        const actual = extractExpirationData(expiresAt, 7200);
        const expected = [false];
        expect(actual).toEqual(expected);
      });

      test('not expired, expiring within threshold', () => {
        const expiresAt = (Date.now() + 5000);
        const actual = extractExpirationData(expiresAt, 7200);
        const expected = [true, true];
        expect(actual).toEqual(expected);
      });

      test('not expired, not expiring within threshold', () => {
        const expiresAt = (Date.now() + 9000);
        const actual = extractExpirationData(expiresAt, 7200);
        const expected = [true, false];
        expect(actual).toEqual(expected);
      });
    });

    describe('invalid data', () => {
      test('invalid expiresAt', () => {
        [{}, [], 's', function() {}].forEach(invalidExpiresAt => {
          // @ts-ignore
          const actual = extractExpirationData(invalidExpiresAt, 7200);
          const expected = [false];
          expect(actual).toEqual(expected);
        })
      });

      test('invalid threshold', () => {
        [{}, [], 's', function() {}].forEach(invalidThreshold => {
          const expiresAt = (Date.now() + 5000).toString();
          // @ts-ignore
          const actual = extractExpirationData(expiresAt, invalidThreshold);
          const expected = [true, true];
          expect(actual).toEqual(expected);
        })
      });
    });
  });
});
