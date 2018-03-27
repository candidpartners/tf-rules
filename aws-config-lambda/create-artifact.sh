#!/usr/bin/env bash
set -e

tmpDir="snitch_deployment"
mkdir ${tmpDir}

#Nuke node_modules
rm -rf src/node_modules

# Copy src
cp -R  src ${tmpDir}/src

# Add the tf index
cp *.tf ${tmpDir}

# Add the js script
cp npm_install.js ${tmpDir}

# Add the tf module
cp -R modules ${tmpDir}/modules

# Zip it all up!
pushd ${tmpDir}; zip -r ../snitch_deployment.zip *; popd
rm -rf ${tmpDir}

