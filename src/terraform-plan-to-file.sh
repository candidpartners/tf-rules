#!/usr/bin/env bash
set -e

file=$1;

pushd ${file}
tfFile=$(find . -name "*.tf" -type f);
echo "Found tf file: " ${tfFile}
basename=$(basename ${tfFile} .tf)

terraform init
terraform plan -no-color > ${basename}-output.txt
rm -rf .terraform
popd

echo "Output modules plan to " ${basename}-output.txt
