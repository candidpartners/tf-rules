#!/usr/bin/env bash
set -e

aws s3 cp ./snitch_deployment.zip s3://volker-static-assets/snitch_deployment.zip
rm ./snitch_deployment.zip