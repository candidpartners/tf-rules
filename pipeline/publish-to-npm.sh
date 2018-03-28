#!/usr/bin/env bash
set -e

pushd src
npm version patch
#git commit -a -m "Bumped version"
version=$(cat ./package.json | jq '.version')
git tag -a ${version} -m ${version}
git push
npm publish --access restricted


# Check if any changes are pending
#git diff --quiet --exit-code HEAD

#if [ "$?" = "0" ]; then
#    set -e
#    git ls-files --modified --deleted


#    echo Publishing snitch ${version}



#    echo Tagging Git Repo with version $version


#    echo Pushing ${version} tag up to repo

#else
#    echo "Error: You have unstaged changes!" 1>&2
#    exit 1
#fi