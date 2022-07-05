import * as esbuild from 'https://deno.land/x/esbuild@v0.14.48/mod.js';
const result = await esbuild.build({
    entryPoints: ['src/index.ts'],
    bundle: true,
    format: 'esm',
    outfile: 'mod.ts',
  })
console.log('result:', result)
esbuild.stop()