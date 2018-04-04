#!/bin/bash
set -e

rm -rf docs

pushd ui/
npm install
npm run build
popd
cp -R ui/build docs/
rm -rf ui/build/*