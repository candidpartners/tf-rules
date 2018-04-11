#!/usr/bin/env bash
set -e

pushd ../src/
npm i
popd

npm i
node generate-static-rules.js
npm run deploy

