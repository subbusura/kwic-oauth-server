module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  testMatch: ['**/tests/**/*.spec.ts'],
  moduleFileExtensions: ['ts', 'js', 'json'],
  setupFilesAfterEnv: [],
  moduleNameMapper: {
    '^nanoid$': '<rootDir>/tests/__mocks__/nanoid.js',
    '^crypto-random-string$': '<rootDir>/tests/__mocks__/crypto-random-string.js'
  }
};
