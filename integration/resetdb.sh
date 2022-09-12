#!/bin/bash

# Copyright 2019 Google LLC. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Based on
# https://github.com/google/trillian/blob/master/scripts/resetdb.sh,
# as of commit e441824 on May 14, 2019. Note original file lacked
# copyright headers, added above based on top-level trillian LICENCE
# and git history.

set -e

usage() {
  cat <<EOF
$(basename $0) [--force] [--verbose] ...
All unrecognised arguments will be passed through to the 'mysql' command.
Accepts environment variables:
- MYSQL_ROOT_USER: A user with sufficient rights to create/reset the Trillian
  database (default: root).
- MYSQL_ROOT_PASSWORD: The password for \$MYSQL_ROOT_USER (default: none).
- MYSQL_HOST: The hostname of the MySQL server (default: localhost).
- MYSQL_PORT: The port the MySQL server is listening on (default: 3306).
- MYSQL_DATABASE: The name to give to the new Trillian user and database
  (default: sigsum_test).
- MYSQL_USER: The name to give to the new Trillian user (default: sigsum_test).
- MYSQL_PASSWORD: The password to use for the new Trillian user
  (default: zaphod).
- MYSQL_USER_HOST: The host that the Trillian user will connect from; use '%' as
  a wildcard (default: localhost).
EOF
}

die() {
  echo "$*" > /dev/stderr
  exit 1
}

collect_vars() {
  # set unset environment variables to defaults
  [ -z ${MYSQL_ROOT_USER+x} ] && MYSQL_ROOT_USER="root"
  [ -z ${MYSQL_HOST+x} ] && MYSQL_HOST="localhost"
  [ -z ${MYSQL_PORT+x} ] && MYSQL_PORT="3306"
  [ -z ${MYSQL_DATABASE+x} ] && MYSQL_DATABASE="sigsum_test"
  [ -z ${MYSQL_USER+x} ] && MYSQL_USER="sigsum_test"
  [ -z ${MYSQL_PASSWORD+x} ] && MYSQL_PASSWORD="zaphod"
  [ -z ${MYSQL_USER_HOST+x} ] && MYSQL_USER_HOST="localhost"
  FLAGS=()

  # handle flags
  FORCE=false
  VERBOSE=false
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --force) FORCE=true ;;
      --verbose) VERBOSE=true ;;
      --help) usage; exit ;;
      *) FLAGS+=("$1")
    esac
    shift 1
  done

  FLAGS+=(-u "${MYSQL_ROOT_USER}")
  FLAGS+=(--host "${MYSQL_HOST}")
  FLAGS+=(--port "${MYSQL_PORT}")

  # Optionally print flags (before appending password)
  [[ ${VERBOSE} = 'true' ]] && echo "- Using MySQL Flags: ${FLAGS[@]}"

  # append password if supplied
  [ -z ${MYSQL_ROOT_PASSWORD+x} ] || FLAGS+=(-p"${MYSQL_ROOT_PASSWORD}")
}

main() {
  collect_vars "$@"

  echo "Warning: about to destroy and reset database '${MYSQL_DATABASE}'"

  [[ ${FORCE} = true ]] || read -p "Are you sure? [Y/N]: " -n 1 -r
  echo # Print newline following the above prompt

  if [ -z ${REPLY+x} ] || [[ $REPLY =~ ^[Yy]$ ]]
  then
      echo "Resetting DB..."
      mysql "${FLAGS[@]}" -e "DROP DATABASE IF EXISTS ${MYSQL_DATABASE};" || \
        die "Error: Failed to drop database '${MYSQL_DATABASE}'."
      mysql "${FLAGS[@]}" -e "CREATE DATABASE ${MYSQL_DATABASE};" || \
        die "Error: Failed to create database '${MYSQL_DATABASE}'."
      mysql "${FLAGS[@]}" -e "CREATE USER IF NOT EXISTS ${MYSQL_USER}@'${MYSQL_USER_HOST}' IDENTIFIED BY '${MYSQL_PASSWORD}';" || \
        die "Error: Failed to create user '${MYSQL_USER}@${MYSQL_USER_HOST}'."
      mysql "${FLAGS[@]}" -e "GRANT ALL ON ${MYSQL_DATABASE}.* TO ${MYSQL_USER}@'${MYSQL_USER_HOST}'" || \
        die "Error: Failed to grant '${MYSQL_USER}' user all privileges on '${MYSQL_DATABASE}'."
      mysql "${FLAGS[@]}" -D ${MYSQL_DATABASE} < "$(dirname "$0")/storage.sql" || \
        die "Error: Failed to create tables in '${MYSQL_DATABASE}' database."
      echo "Reset Complete"
  fi
}

main "$@"
