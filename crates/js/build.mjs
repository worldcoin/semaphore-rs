// build.js
// This script reads the wasm binary, inlines it as a base64 string in a new loader file,
// and then regenerates package.json to point to the new inline loader.

import fs from 'fs';
import path from 'path';

// Define the package output directory (adjust if needed)
const pkgDir = path.resolve('pkg');

// Load the original package.json
const pkgJsonPath = path.join(pkgDir, 'package.json');
const pkgJson = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));

// Read the wasm binary and encode it to base64
const wasmPath = path.join(pkgDir, 'semaphore_rs_js_bg.wasm');
const wasmBuffer = fs.readFileSync(wasmPath);
const wasmBase64 = wasmBuffer.toString('base64');

// Generate the inline loader file which will decode the base64 string,
// instantiate the wasm module synchronously, and then call initSync.
const inlineLoaderContent = `
// This file is auto-generated by build.js.
// It inlines the wasm module as a base64 string and loads it synchronously.

import { initSync } from './semaphore_rs_js.js';

const base64Wasm = "${wasmBase64}";

// Convert a base64 string to a Uint8Array
function base64ToUint8Array(base64) {
  if (typeof atob === 'function') {
    const binaryString = atob(base64);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
  } else if (typeof Buffer === 'function') {
    // In Node.js, Buffer is available.
    return new Uint8Array(Buffer.from(base64, 'base64'));
  } else {
    throw new Error('No base64 decoder available');
  }
}

const wasmBytes = base64ToUint8Array(base64Wasm);

// Initialize the generated bindings with the inlined wasm instance.
initSync({ module: wasmBytes });

export * from './semaphore_rs_js.js';
`;

// Write the inline loader file (e.g. index.js)
const inlineLoaderPath = path.join(pkgDir, 'index.js');
fs.writeFileSync(inlineLoaderPath, inlineLoaderContent.trim());
console.log(`Generated inline loader: ${inlineLoaderPath}`);

// Regenerate package.json to update "main" and the list of published files.
const newPkgJson = {
  ...pkgJson,
  // Point to the new inline loader
  main: "index.js",
  // Publish only the inline loader and the original generated JS and types,
  // excluding the raw wasm file.
  files: [
    "index.js",
    "semaphore_rs_js.js",
    "semaphore_rs_js.d.ts"
  ]
};

fs.writeFileSync(pkgJsonPath, JSON.stringify(newPkgJson, null, 2));
console.log(`Updated package.json: ${pkgJsonPath}`);

console.log("Build complete: Wasm module inlined and package.json regenerated.");

