#!/usr/bin/env bash

version=$(cat ./package.json | jq '.version')

echo Publishing @CandidPartners/tf-parse $version
npm publish --access public

echo Tagging Git Repo with version $version
git tag -a $version -m $version

echo Pushing $version tag up to repo
git push origin $version

