import { Authenticator, extractAuthData, extractExpirationData } from './authenticator';
import { makeClient } from './test-utils/client';
import MemStorage from './test-utils/mem-storage';
import { WebAuth } from 'auth0-js';
import { AuthStorage, Storage } from './storage';

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
      expect(client.authorize).toBeCalledWith({ responseType: 'token id_token' });

      auth.promptLogin('/page-1', { prompt: 'none' });
      expect(authStorage.retrieveLoginLocation()).toEqual('/page-1');
      expect(client.authorize).toBeCalledWith({ responseType: 'token id_token', prompt: 'none' });
    });

    describe('handleLoginSuccess', () => {
      test('with response data', () => {
        client.parseHash = jest.fn().mockImplementation(cb => cb(undefined, {
          accessToken: 'a',
          idTokenPayload: { sub: 'u' },
          expiresIn: 7200
        }));

        const expectedExpiresAt = Date.now() + (7200 * 1000);

        auth.handleLoginSuccess().then(({ accessToken, userId, expiresAt }) => {
          expect(accessToken).toEqual('a');
          expect(userId).toEqual('u');
          expect(Math.trunc(expiresAt / 1000)).toEqual(Math.trunc(expectedExpiresAt / 1000));
        });
      });

      test('with error', () => {
        client.parseHash = jest.fn().mockImplementation(cb => cb(new Error('error!'), undefined));

        auth.handleLoginSuccess()
          .then(() => {})
          .catch(error => {
            expect(error.message).toEqual('error!');
          });
      });

      test('with neither response nor error', () => {
        client.parseHash = jest.fn().mockImplementation(cb => cb(undefined, undefined));

        auth.handleLoginSuccess()
          .then(() => {})
          .catch(error => {
            expect(error.message).toEqual('parseHash neither parsed the hash successfully nor returned an error');
          });
      });
    });


  });

  describe('extractAuthData', () => {
    test('with valid data', () => {
      const parsed = {
        accessToken: 'a',
        idTokenPayload: { sub: 'u' },
        expiresIn: 7200
      };

      const expectedExpiresAt = Date.now() + (parsed.expiresIn * 1000);

      let actual, expected;

      actual = extractAuthData(parsed);

      expected = {
        accessToken: 'a',
        userId: 'u',
        expiresAt: expectedExpiresAt
      };
      expect(actual).toEqual(expected);
    });
  });

  describe('extractExpirationData', () => {
    describe('valid data', () => {
      test('null expiresAt', () => {
        const actual = extractExpirationData(null, 7200);
        const expected = [false];
        expect(actual).toEqual(expected);
      });

      test('expiresAt is in the past', () => {
        const expiresAt = (Date.now() - 10000).toString();
        const actual = extractExpirationData(expiresAt, 7200);
        const expected = [false];
        expect(actual).toEqual(expected);
      });

      test('not expired, expiring within threshold', () => {
        const expiresAt = (Date.now() + 5000).toString();
        const actual = extractExpirationData(expiresAt, 7200);
        const expected = [true, true];
        expect(actual).toEqual(expected);
      });

      test('not expired, not expiring within threshold', () => {
        const expiresAt = (Date.now() + 9000).toString();
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
