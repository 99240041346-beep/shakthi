#!/usr/bin/env bash
set -euo pipefail
rm -rf .deploy_src
mkdir -p .deploy_src
tar -xzf campus_shakthi_src.tar.gz -C .deploy_src
cp -a .deploy_src/. .
python -m pip install -r requirements.txt
