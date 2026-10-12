import { env } from 'node:process';

export default {
  branches: ['main'],
  plugins: [
    '@semantic-release/commit-analyzer',
    '@semantic-release/release-notes-generator',
    ['@semantic-release/npm', { npmPublish: env.NPM_PUBLISH === 'true' }],
    '@semantic-release/github',
  ],
};
