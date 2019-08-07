import { makeAuthStorage } from './storage';
import MemStorage from './test-utils/mem-storage';

describe('storage', () => {
  describe('makeAuthStorage', () => {
    const storage = new MemStorage();
    const authStorage = makeAuthStorage({ storage });

    test('loginLocation', () => {
      const loginLocation = '/page';
      authStorage.storeLoginLocation(loginLocation);
      expect(authStorage.retrieveLoginLocation()).toEqual(loginLocation);
      authStorage.removeLoginLocation();
      expect(authStorage.retrieveLoginLocation()).toEqual(undefined);
    });

    test('expiresAt', () => {
      const expiresAt = 1000000;
      authStorage.storeExpiresAt(expiresAt);
      expect(authStorage.retrieveExpiresAt()).toEqual(expiresAt);
      authStorage.removeExpiresAt();
      expect(authStorage.retrieveExpiresAt()).toEqual(undefined);
    });

    test('nonce', () => {
      const nonce = 1234;
      authStorage.storeNonce(nonce);
      expect(authStorage.retrieveNonce()).toEqual(nonce);
      authStorage.removeNonce();
      expect(authStorage.retrieveNonce()).toEqual(undefined);
    });
  });
});
