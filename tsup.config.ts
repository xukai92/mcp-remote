import { defineConfig } from 'tsup'

export default defineConfig({
  entry: ['src/cli/client.ts', 'src/cli/proxy.ts', 'src/react/index.ts'],
  format: ['esm'],
  dts: true,
  clean: true,
  outDir: 'dist',
  external: ['react'],
})
