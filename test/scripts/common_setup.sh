#!/usr/bin/env bash
# Common setup for all CLI tests
# This file should be sourced by individual test scripts

set -euo pipefail

# Disable pipefail for specific commands that may trigger SIGPIPE
disable_pipefail() {
  set +o pipefail
}

enable_pipefail() {
  set -o pipefail
}

# Reset secret1.age to known content (useful since tests may modify it)
reset_secret1() {
  echo "hello" | agenix edit secret1.age
}
