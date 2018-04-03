#!/bin/bash

pushd ui/
npm install
npm run build
popd
rsync -avz --delete "ui/build/" "docs/"
rm -rf ui/build/*