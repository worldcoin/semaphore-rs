#!/usr/bin/env bash

set -e

wasm-pack build -t web
node build.mjs

cd pkg
npm pack
npm publish
cd ..

