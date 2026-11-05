#!/bin/bash

#
# Usage: ./test-mtls.sh
#

set -euo pipefail

cd "$(dirname "$0")"
export SIGSUM_LOGSERVER_CONFIG=/dev/null
primary_pid=
witness_pid=

cleanup() {
    if [[ -n "$primary_pid" ]]; then
        kill "$primary_pid" 2>/dev/null || true
        wait "$primary_pid" 2>/dev/null || true
    fi
    if [[ -n "$witness_pid" ]]; then
        kill "$witness_pid" 2>/dev/null || true
        wait "$witness_pid" 2>/dev/null || true
    fi
}
trap cleanup EXIT

GOBIN=$(pwd)/bin go install ../cmd/sigsum-log-primary
GOBIN=$(pwd)/bin go install ../cmd/sigsum-mktree
GOBIN=$(pwd)/bin go install sigsum.org/sigsum-go/cmd/sigsum-key
GOBIN=$(pwd)/bin go install ./mtls-witness

rm -rf tmp
mkdir tmp
cd tmp

../bin/sigsum-key generate -o log.key
../bin/sigsum-mktree --sth-file=sth

# Witness key is not used, so it's hardcoded to a dummy value
cat >policy <<EOF
witness test d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a https://127.0.0.1:7777
quorum test
EOF

# Root CA (both for mTLS client cert and witness HTTPS cert)
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out root.key
openssl req -new -x509 -sha256 -key root.key -out root.crt \
    -days 1 -subj '/CN=Sigsum mTLS example root' \
    -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \
    -addext 'keyUsage=critical,keyCertSign'

# mTLS leaf
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out client.key
openssl req -new -sha256 \
    -key client.key -out client.csr \
    -subj '/CN=Sigsum mTLS example client'
cat >client.ext <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
EOF
openssl x509 -req -sha256 \
    -in client.csr -out client.crt \
    -CA root.crt -CAkey root.key \
    -CAcreateserial -days 1 -extfile client.ext

# mTLS certificate chain
cat client.crt root.crt >client-chain.crt

# Witness HTTPS cert
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -nodes -keyout server.key -out server.csr \
    -subj /CN=localhost \
    -addext 'subjectAltName=IP:127.0.0.1' \
    -addext 'extendedKeyUsage=serverAuth'
openssl x509 -req -in server.csr \
    -CA root.crt -CAkey root.key \
    -CAcreateserial -days 1 -copy_extensions copy \
    -out server.crt

# Start mock witness that requires mTLS for incoming add-checkpoint requests
../bin/mtls-witness -cert server.crt -key server.key -ca root.crt 2>witness.log &
witness_pid=$!

# Start primary which will POST /add-checkpoint to our mock witness with mTLS
SSL_CERT_FILE=root.crt ../bin/sigsum-log-primary \
    --backend=ephemeral \
    --key-file=log.key \
    --sth-file=sth \
    --policy-file=policy \
    --interval=1s \
    --mtls-cert=client-chain.crt \
    --mtls-key=client.key \
    >primary.log 2>&1 &
primary_pid=$!

if ! wait "$witness_pid"; then
    witness_pid=
    cat primary.log witness.log >&2
    echo "FAIL: mTLS checkpoint request" >&2
    exit 1
fi
witness_pid=

echo "PASS: mTLS checkpoint request"
