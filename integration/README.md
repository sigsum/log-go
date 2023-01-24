# Sigsum log integration tests

These tests start a sigsum-log-primary and sigsum-log-secondary, and
corresponding trillian servers, to verify basic functionality of the
complete system.

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

There are three modes of running the tests, basic mode `./test.sh`,
extensive mode testing failover, `./test.sh --extended`, and ephemeral
mode which doesn't store any data to disk and doesn't use trillian,
`./test.sh --ephemeral`.
