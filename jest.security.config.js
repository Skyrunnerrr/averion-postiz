/** @type {import('jest').Config} */
module.exports = {
  testEnvironment: 'node',
  setupFiles: ['reflect-metadata'],
  testMatch: [
    '<rootDir>/libraries/helpers/src/auth/provider.credential.spec.ts',
    '<rootDir>/libraries/helpers/src/auth/deployment.gates.spec.ts',
    '<rootDir>/libraries/nestjs-libraries/src/integrations/social/instagram.standalone.scopes.spec.ts',
    '<rootDir>/libraries/helpers/src/utils/refresh.channel.outcome.spec.ts',
  ],
  transform: {
    '^.+\\.ts$': [
      'ts-jest',
      {
        tsconfig: {
          esModuleInterop: true,
          allowSyntheticDefaultImports: true,
          experimentalDecorators: true,
          emitDecoratorMetadata: true,
          strict: false,
          skipLibCheck: true,
          module: 'commonjs',
          target: 'es2020',
          baseUrl: '.',
          paths: {
            '@gitroom/nestjs-libraries/*': ['libraries/nestjs-libraries/src/*'],
            '@gitroom/helpers/*': ['libraries/helpers/src/*'],
            '@gitroom/backend/*': ['apps/backend/src/*'],
            '@gitroom/orchestrator/*': ['apps/orchestrator/src/*'],
          },
        },
      },
    ],
  },
  moduleNameMapper: {
    '^@gitroom/nestjs-libraries/(.*)$':
      '<rootDir>/libraries/nestjs-libraries/src/$1',
    '^@gitroom/helpers/(.*)$': '<rootDir>/libraries/helpers/src/$1',
    '^@gitroom/backend/(.*)$': '<rootDir>/apps/backend/src/$1',
    '^@gitroom/orchestrator/(.*)$': '<rootDir>/apps/orchestrator/src/$1',
  },
};
