#!/usr/bin/env bash
set -xeuo pipefail

pytest -v protocol_test.py -s -o log_cli=true
