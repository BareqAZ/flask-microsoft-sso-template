#!/usr/bin/env bash

# Find the absolute path regardless of where this script is being executed from.
SRC=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

set -e

linter_path="$@"

[[ -z $linter_path ]] && linter_path="$SRC/src"

# --- flake8 ---
flake8 $linter_path --config $SRC/linter_config.cfg --exit-zero

# --- black ---
black $linter_path

# --- isort ---
isort $linter_path --settings-path $SRC/linter_config.cfg

# --- radon ---
radon mi -s -n B $linter_path
