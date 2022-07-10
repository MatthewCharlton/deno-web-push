import * as esbuild from 'https://deno.land/x/esbuild@v0.14.48/mod.js';
import { denoPlugin } from 'https://deno.land/x/esbuild_deno_loader@0.5.0/mod.ts';

const cjs = await esbuild.build({
  plugins: [denoPlugin()],
  entryPoints: ['src/index.ts'],
  bundle: true,
  format: 'cjs',
  outfile: 'index.js',
});
console.log('result:', cjs);
esbuild.stop();

const decoder = new TextDecoder('utf-8');
const encoder = new TextEncoder();

Deno.writeFileSync(
  'index.js',
  encoder.encode(
    decoder.decode(Deno.readFileSync('index.js')).replace(
      '"use strict";',
      `"use strict";
if (typeof Deno === 'undefined') {
  globalThis.addEventListener = () => {};
  globalThis.Deno = {
    env: {
get: () => {}
    },
    args: [],
    errors: {
    PermissionDenied: Error
  },
  build:{
arch: 'x86_64'
}
};
globalThis.crypto= require('node:crypto').webcrypto;
}
const CryptoKey =  globalThis.crypto.CryptoKey;

`
    )
  )
);

const esm = await esbuild.build({
  plugins: [denoPlugin()],
  entryPoints: ['src/index.ts'],
  bundle: true,
  format: 'esm',
  outfile: 'mod.ts',
});
console.log('result:', esm);
esbuild.stop();
