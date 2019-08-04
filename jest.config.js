module.exports = {
  "roots": [
    "<rootDir>/src"
  ],
  "transform": {
    "^.+\\.ts$": "ts-jest"
  },
  "setupFiles": [
    "./src/test-utils/setup.js"
  ]
};
