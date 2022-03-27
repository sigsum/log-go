#!/bin/bash

set -eu
trap cleanup EXIT

function main() {
	log_dir=$(mktemp -d)
	info "writing logs to $log_dir"

	check_go_deps
	trillian_setup conf/trillian.config
	sigsum_setup   conf/sigsum.config
	client_setup   conf/client.config
	check_setup

	run_tests
}

function check_go_deps() {
	[[ $(command -v trillian_log_signer) ]] || die "Hint: go install github.com/google/trillian/cmd/trillian_log_signer@v1.3.13"
	[[ $(command -v trillian_log_server) ]] || die "Hint: go install github.com/google/trillian/cmd/trillian_log_server@v1.3.13"
	[[ $(command -v createtree)          ]] || die "Hint: go install github.com/google/trillian/cmd/createtree@v1.3.13"
	[[ $(command -v deletetree)          ]] || die "Hint: go install github.com/google/trillian/cmd/deletetree@v1.3.13"
	[[ $(command -v sigsum_log_go)       ]] || die "Hint: go install git.sigsum.org/sigsum-log-go/cmd/sigsum_log_go@v0.3.5"
	[[ $(command -v sigsum-debug)        ]] || die "Hint: see sigsum-tools-go repo, branch rgdd/sigsum-debug"
}

function client_setup() {
	source $1

	cli_pub=$(echo $cli_priv | sigsum-debug pubkey)
	cli_key_hash=$(echo $cli_pub | sigsum-debug hashkey)

	[[ $cli_domain_hint =~ ^_sigsum_v0..+ ]] ||
		die "must have a valid domain hint"

	for line in $(dig +short -t txt $cli_domain_hint); do
		key_hash=${line:1:${#line}-2}
		if [[ $key_hash == $cli_key_hash ]]; then
			return
		fi
	done

	die "must have a properly configured domain hint"
}

function trillian_setup() {
	source $1

	trillian_log_server\
		-rpc_endpoint=$tsrv_rpc\
		-http_endpoint=$tsrv_http\
		-log_dir=$log_dir 2>/dev/null &
	tsrv_pid=$!
	info "started Trillian log server (pid $tsrv_pid)"

	trillian_log_signer\
		-force_master\
		-rpc_endpoint=$tseq_rpc\
		-http_endpoint=$tseq_http\
		-log_dir=$log_dir 2>/dev/null &

	tseq_pid=$!
	info "started Trillian log sequencer (pid $tseq_pid)"

	ssrv_tree_id=$(createtree --admin_server $tsrv_rpc 2>/dev/null)
	[[ $? -eq 0 ]] ||
		die "must provision a new Merkle tree"

	info "provisioned Merkle tree with id $ssrv_tree_id"
}

function sigsum_setup() {
	source $1

	wit1_priv=$(sigsum-debug genkey)
	wit1_pub=$(echo $wit1_priv | sigsum-debug pubkey)
	wit1_key_hash=$(echo $wit1_pub | sigsum-debug hashkey)

	wit2_priv=$(sigsum-debug genkey)
	wit2_pub=$(echo $wit2_priv | sigsum-debug pubkey)
	wit2_key_hash=$(echo $wit2_pub | sigsum-debug hashkey)

	ssrv_witnesses=$wit1_key_hash,$wit2_key_hash
	ssrv_priv=$(sigsum-debug genkey)
	ssrv_pub=$(echo $ssrv_priv | sigsum-debug pubkey)

	sigsum_log_go\
		-prefix=$ssrv_prefix\
		-trillian_id=$ssrv_tree_id\
		-shard_interval_start=$ssrv_shard_start\
		-key=$ssrv_priv\
		-witnesses=$ssrv_witnesses\
		-interval=$ssrv_interval\
		-http_endpoint=$ssrv_endpoint\
		-log_dir=$log_dir -v=3 2>/dev/null &
	ssrv_pid=$!

	info "started Sigsum log server on $ssrv_endpoint (pid $ssrv_pid)"
}

function cleanup() {
	set +e

	info "cleaning up, please wait..."
	sleep 1

	kill -2 $ssrv_pid
	kill -2 $tseq_pid
	while :; do
		sleep 1

		ps -p $tseq_pid >/dev/null && continue
		ps -p $ssrv_pid >/dev/null && continue

		break
	done

	info "stopped Trillian log sequencer"
	info "stopped Sigsum log server"

	deletetree -admin_server=$tsrv_rpc -log_id=$ssrv_tree_id ||
		warn "failed deleting provisioned Merkle tree"

	info "deleteted provisioned Merkle tree"

	kill -2 $tsrv_pid
	while :; do
		sleep 1

		ps -p $tsrv_pid >/dev/null && continue

		break
	done

	info "stopped Trillian log server"
}

function check_setup() {
	sleep 3

	ps -p $tseq_pid >/dev/null || die "must have Trillian log sequencer"
	ps -p $tsrv_pid >/dev/null || die "must have Trillian log server"
	ps -p $ssrv_pid >/dev/null || die "must have Sigsum log server"
}

function run_tests() {
	info "TODO: add tests"
}

function die() {
	echo -e "\e[90m$(date +"%Y-%m-%d %H:%M:%S")\e[0m [\e[1;31mFATA\e[0m] $@" >&2
	exit 1
}

function info() {
	echo -e "\e[90m$(date +"%Y-%m-%d %H:%M:%S")\e[0m [\e[94mINFO\e[0m] $@" >&2
}

function warn() {
	echo -e "\e[90m$(date +"%Y-%m-%d %H:%M:%S")\e[0m [\e[33mWARN\e[0m] $@" >&2
}

main
