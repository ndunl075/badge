import { fileURLToPath } from 'node:url'
import { defineConfig } from 'vitest/config'

// Tests run against TypeScript sources, not build output, so `pnpm test` works
// on a clean checkout without a build step. Package `exports` still point at
// dist/ for consumers.
export default defineConfig({
  resolve: {
    alias: [
      {
        find: /^@badge\/([^/]+)$/,
        replacement: fileURLToPath(new URL('./packages/$1/src/index.ts', import.meta.url)),
      },
    ],
  },
  test: {
    include: ['packages/*/src/**/*.test.ts', 'packages/*/test/**/*.test.ts'],
  },
})
