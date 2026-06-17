export default {
  rootDir: '../',
  testEnvironment: 'node',
  collectCoverageFrom: [
    'src/**/*.js',
    '!src/manifest.json',
  ],
  coveragePathIgnorePatterns: [
    '/node_modules/',
  ],
  testMatch: [
    '<rootDir>/tests/unit/specs/**/*.spec.js',
  ],
};
