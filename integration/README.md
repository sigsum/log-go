# Sigsum log integration tests

These tests start a sigsum-log-primary and sigsum-log-secondary, and
corresponding trillian servers, to verify basic functionality of the
complete system.

## Dependencies

Before running tests, first install the tools listed in
`check_go_deps` in `test.sh`. The trillian servers also need a
database, see next section.

FIXME: Document how to ensure that certain of the dependencies, in
particular, commands like `sigsum-log-primary`, are built from local
sources possibly with modifications.

## Database

First install the database server. E.g., on a Debian GNU/Linux system,
run `apt-get install mariadb-server && mysql_secure_installation` as
root, with default ansers to all questions.

Next, run the script `resetdb.sh`, to prepare needed database tables
and users. This script needs to run with sufficient privileges to
modify the database's user table; with a default install as above,
the simplest way of getting sufficient privileges is to run the script
as root.

If successful, the script creates a user `sigsum_test` and a database
`sigsum_test`, and empty tables according to the schema `storage.sql`.

## Running tests

There are two modes of running the tests, basic mode `./test.sh`, and
extensive mode, `./test.sh extended`.
