#!/usr/bin/env bash

# Check if any changes are pending
git diff --quiet --exit-code HEAD

if [ "$?" = "0" ]; then
    git ls-files --modified --deleted
    version=$(cat ./package.json | jq '.version')

    echo Publishing @CandidPartners/snitch ${version}
    npm publish --access public

    echo Tagging Git Repo with version $version
    git tag -a ${version} -m ${version}

    echo Pushing ${version} tag up to repo
    git push origin ${version}
else
    echo "Error: You have unstaged changes!" 1>&2
    exit 1
fi