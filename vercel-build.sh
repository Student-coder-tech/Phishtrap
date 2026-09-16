#!/bin/bash
set -e
echo "Building client..."
npm run build --workspace client
echo "Copying client/dist to root dist..."
rm -rf dist
cp -r client/dist dist
echo "Building server..."
npm run build --workspace server
echo "Build complete."
