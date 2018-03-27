#!/usr/bin/env bash
set -e

tmpDir="snitch_deployment"
mkdir ${tmpDir}

# Zip up src
zip -r ${tmpDir}/function.zip src

# Add the tf index
cp bin_template/*.tf ${tmpDir}

# Add the tf module
cp -R terraform/snitch_module ${tmpDir}/snitch_module

# Zip it all up!
zip -r snitch_deployment.zip ${tmpDir}
rm -rf ${tmpDir}

