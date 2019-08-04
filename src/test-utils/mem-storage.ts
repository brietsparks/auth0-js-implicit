export default class MemStorage {
  store: { [key: string]: any };

  constructor(initial = {}) {
    this.store = initial;
  }

  setItem(key: string, val: any) {
    this.store[key] = val
  };

  getItem(key: string) {
    return this.store[key];
  }

  removeItem(key: string) {
    delete this.store[key]
  }
}

