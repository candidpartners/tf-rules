#!/usr/bin/env bash
set -e

node generate-static-rules.js
npm i
npm run deploy

