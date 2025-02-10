#!/usr/bin/env bash

set -e

function build_and_publish_pkg() {
  target=$1
  
  wasm-pack build -t $target -d "pkg-$target"
  jq --arg target "-$target" '.name = "semaphore-rs" + $target' "pkg-$target"/package.json > package.json.tmp && mv package.json.tmp "pkg-$target"/package.json

  if [[ "${DRY_RUN,,}" == "true" || "$DRY_RUN" == "1" ]]; then
    echo "Skipping publish"
  else
    cd "pkg-$target"
    npm pack
    npm publish
    cd ..
  fi
}

build_and_publish_pkg nodejs
build_and_publish_pkg bundler

