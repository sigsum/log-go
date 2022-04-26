#!/bin/bash

#
# Requirements to run
#
#   - Install required dependencies, see check_go_deps()
#   - Add the empty values in conf/client.config
#
# Usage:
#
#     $ ./test.sh
#

set -eu
trap cleanup EXIT

function main() {
	log_dir=$(mktemp -d)

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
	[[ $(command -v sigsum_log_go)       ]] || die "Hint: go install git.sigsum.org/log-go/cmd/sigsum_log_go@latest"
	[[ $(command -v sigsum-debug)        ]] || die "Hint: install sigsum-debug from sigsum-go, branch merge/sigsum-debug"
}

function client_setup() {
	info "setting up client"
	source $1

	cli_pub=$(echo $cli_priv | sigsum-debug key public)
	cli_key_hash=$(echo $cli_pub | sigsum-debug key hash)

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
	info "setting up Trillian"
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
	info "setting up Sigsum server"
	source $1

	wit1_priv=$(sigsum-debug key private)
	wit1_pub=$(echo $wit1_priv | sigsum-debug key public)
	wit1_key_hash=$(echo $wit1_pub | sigsum-debug key hash)

	wit2_priv=$(sigsum-debug key private)
	wit2_pub=$(echo $wit2_priv | sigsum-debug key public)
	wit2_key_hash=$(echo $wit2_pub | sigsum-debug key hash)

	ssrv_witnesses=$wit1_pub,$wit2_pub
	ssrv_priv=$(sigsum-debug key private)
	ssrv_pub=$(echo $ssrv_priv | sigsum-debug key public)
	ssrv_key_hash=$(echo $ssrv_pub | sigsum-debug key hash)

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

	log_url=$ssrv_endpoint/$ssrv_prefix/sigsum/v0
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

	if ! deletetree -admin_server=$tsrv_rpc -log_id=$ssrv_tree_id; then
		warn "failed deleting provisioned Merkle tree"
	else
		info "deleteted provisioned Merkle tree"
	fi

	kill -2 $tsrv_pid
	while :; do
		sleep 1

		ps -p $tsrv_pid >/dev/null && continue

		break
	done

	info "stopped Trillian log server"

	printf "\n  Press any key to delete logs in $log_dir"
	read dummy

	rm -rf $log_dir
}

function check_setup() {
	sleep 3

	ps -p $tseq_pid >/dev/null || die "must have Trillian log sequencer"
	ps -p $tsrv_pid >/dev/null || die "must have Trillian log server"
	ps -p $ssrv_pid >/dev/null || die "must have Sigsum log server"
}

function run_tests() {
	num_leaf=5

	test_signed_tree_head 0
	for i in $(seq 1 $num_leaf); do
		test_add_leaf $i
	done

	info "waiting for $num_leaf leaves to be merged..."
	sleep ${ssrv_interval::-1}

	test_signed_tree_head $num_leaf
	for i in $(seq 1 $(( $num_leaf - 1 ))); do
		test_consistency_proof $i $num_leaf
	done

	test_cosignature $wit1_key_hash $wit1_priv
	test_cosignature $wit2_key_hash $wit2_priv

	info "waiting for cosignature to be available..."
	sleep ${ssrv_interval::-1}

	test_cosigned_tree_head $num_leaf
	for i in $(seq 1 $num_leaf); do
		test_inclusion_proof $num_leaf $i $(( $i - 1 ))
	done

	for i in $(seq 1 $num_leaf); do
		test_get_leaf $i $(( $i - 1 ))
	done

	warn "no signatures and merkle proofs were verified"
}

function test_signed_tree_head() {
	desc="GET tree-head-to-sign (tree size $1)"
	curl -s -w "%{http_code}" $log_url/get-tree-head-to-sign \
		>$log_dir/rsp

	if [[ $(status_code) != 200 ]]; then
		fail "$desc: http status code $(status_code)"
		return
	fi

	if ! keys "timestamp" "tree_size" "root_hash" "signature"; then
		fail "$desc: ascii keys in response $(debug_response)"
		return
	fi

	now=$(date +%s)
	if [[ $(value_of "timestamp") -gt $now ]]; then
		fail "$desc: timestamp $(value_of "timestamp") is too large"
		return
	fi
	if [[ $(value_of "timestamp") -lt $(( $now - ${ssrv_interval::-1} )) ]]; then
		fail "$desc: timestamp $(value_of "timestamp") is too small"
		return
	fi

	if [[ $(value_of "tree_size") != $1 ]]; then
		fail "$desc: tree size $(value_of "tree_size")"
		return
	fi

	# TODO: verify tree head signature
	pass $desc
}

function test_cosigned_tree_head() {
	desc="GET get-tree-head-cosigned (all witnesses)"
	curl -s -w "%{http_code}" $log_url/get-tree-head-cosigned \
		>$log_dir/rsp

	if [[ $(status_code) != 200 ]]; then
		fail "$desc: http status code $(status_code)"
		return
	fi

	if ! keys "timestamp" "tree_size" "root_hash" "signature" "cosignature" "key_hash"; then
		fail "$desc: ascii keys in response $(debug_response)"
		return
	fi

	now=$(date +%s)
	if [[ $(value_of "timestamp") -gt $now ]]; then
		fail "$desc: timestamp $(value_of "timestamp") is too large"
		return
	fi
	if [[ $(value_of "timestamp") -lt $(( $now - ${ssrv_interval::-1} * 2 )) ]]; then
		fail "$desc: timestamp $(value_of "timestamp") is too small"
		return
	fi

	if [[ $(value_of "tree_size") != $1 ]]; then
		fail "$desc: tree size $(value_of "tree_size")"
		return
	fi

	for got in $(value_of key_hash); do
		found=""
		for want in $wit1_key_hash $wit2_key_hash; do
			if [[ $got == $want ]]; then
				found=true
			fi
		done

		if [[ -z $found ]]; then
			fail "$desc: missing witness $got"
			return
		fi
	done

	# TODO: verify tree head signature
	# TODO: verify tree head cosignatures
	pass $desc
}

function test_inclusion_proof() {
	desc="POST get-inclusion-proof (tree_size $1, data \"$2\", index $3)"
	signature=$(echo $2 | sigsum-debug leaf sign -k $cli_priv -h $ssrv_shard_start)
	leaf_hash=$(echo $2 | sigsum-debug leaf hash -k $cli_key_hash -s $signature -h $ssrv_shard_start)
	curl -s -w "%{http_code}" $log_url/get-inclusion-proof/$1/$leaf_hash >$log_dir/rsp

	if [[ $(status_code) != 200 ]]; then
		fail "$desc: http status code $(status_code)"
		return
	fi

	if ! keys "leaf_index" "inclusion_path"; then
		fail "$desc: ascii keys in response $(debug_response)"
		return
	fi

	if [[ $(value_of leaf_index) != $3 ]]; then
		fail "$desc: wrong leaf index $(value_of leaf_index)"
		return
	fi

	# TODO: verify inclusion proof
	pass $desc
}

function test_consistency_proof() {
	desc="POST get-consistency-proof (old_size $1, new_size $2)"
	curl -s -w "%{http_code}" $log_url/get-consistency-proof/$1/$2 >$log_dir/rsp

	if [[ $(status_code) != 200 ]]; then
		fail "$desc: http status code $(status_code)"
		return
	fi

	if ! keys "consistency_path"; then
		fail "$desc: ascii keys in response $(debug_response)"
		return
	fi

	# TODO: verify consistency proof
	pass $desc
}

function test_get_leaf() {
	desc="GET get-leaves (data \"$1\", index $2)"
	curl -s -w "%{http_code}" $log_url/get-leaves/$2/$2 >$log_dir/rsp

	if [[ $(status_code) != 200 ]]; then
		fail "$desc: http status code $(status_code)"
		return
	fi

	if ! keys "shard_hint" "checksum" "signature" "key_hash"; then
		fail "$desc: ascii keys in response $(debug_response)"
		return
	fi

	if [[ $(value_of shard_hint) != $ssrv_shard_start ]]; then
		fail "$desc: wrong shard hint $(value_of shard_hint)"
		return
	fi

	preimage=$(openssl dgst -binary <(echo $1) | base16)
	checksum=$(openssl dgst -binary <(echo $preimage | base16 -d) | base16)
	if [[ $(value_of checksum) != $checksum ]]; then
		fail "$desc: wrong checksum $(value_of checksum)"
		return
	fi

	if [[ $(value_of key_hash) != $cli_key_hash ]]; then
		fail "$desc: wrong key hash $(value_of key_hash)"
	fi

	# TODO: check leaf signature
	pass $desc
}

function test_add_leaf() {
	desc="POST add-leaf (data \"$1\")"
	echo "shard_hint=$ssrv_shard_start" > $log_dir/req
	echo "preimage=$(openssl dgst -binary <(echo $1) | base16)" >> $log_dir/req
	echo "signature=$(echo $1 |
		sigsum-debug leaf sign -k $cli_priv -h $ssrv_shard_start)" >> $log_dir/req
	echo "verification_key=$cli_pub" >> $log_dir/req
	echo "domain_hint=$cli_domain_hint" >> $log_dir/req
	cat $log_dir/req |
		curl -s -w "%{http_code}" --data-binary @- $log_url/add-leaf \
		>$log_dir/rsp

	if [[ $(status_code) != 200 ]]; then
		fail "$desc: http status code $(status_code)"
		return
	fi

	if ! keys; then
		fail "$desc: ascii keys in response $(debug_response)"
		return
	fi

	pass $desc
}

function test_cosignature() {
	desc="POST add-cosignature (witness $1)"
	echo "key_hash=$1" > $log_dir/req
	echo "cosignature=$(curl -s $log_url/get-tree-head-to-sign |
		sigsum-debug head sign -k $2 -h $ssrv_key_hash)" >> $log_dir/req
	cat $log_dir/req |
		curl -s -w "%{http_code}" --data-binary @- $log_url/add-cosignature \
		>$log_dir/rsp

	if [[ $(status_code) != 200 ]]; then
		fail "$desc: http status code $(status_code)"
		return
	fi

	if ! keys; then
		fail "$desc: ascii keys in response $(debug_response)"
		return
	fi

	pass $desc
}

function debug_response() {
	echo ""
	cat $log_dir/rsp
}

function status_code() {
	tail -n1 $log_dir/rsp
}

function value_of() {
	while read line; do
		key=$(echo $line | cut -d"=" -f1)
		if [[ $key != $1 ]]; then
			continue
		fi

		value=$(echo $line | cut -d"=" -f2)
		echo $value
	done < <(head --lines=-1 $log_dir/rsp)
}

function keys() {
	declare -A map
	map[thedummystring]=to_avoid_error_on_size_zero
	while read line; do
		key=$(echo $line | cut -d"=" -f1)
		map[$key]=ok
	done < <(head --lines=-1 $log_dir/rsp)

	if [[ $# != $(( ${#map[@]} - 1 )) ]]; then
		return 1
	fi
	for key in $@; do
		if [[ -z ${map[$key]} ]]; then
			return 1
		fi
	done
	return 0
}

function die() {
	echo -e "\e[37m$(date +"%y-%m-%d %H:%M:%S %Z")\e[0m [\e[31mFATA\e[0m] $@" >&2
	exit 1
}

function info() {
	echo -e "\e[37m$(date +"%y-%m-%d %H:%M:%S %Z")\e[0m [\e[94mINFO\e[0m] $@" >&2
}

function warn() {
	echo -e "\e[37m$(date +"%y-%m-%d %H:%M:%S %Z")\e[0m [\e[93mWARN\e[0m] $@" >&2
}

function pass() {
	echo -e "\e[37m$(date +"%y-%m-%d %H:%M:%S %Z")\e[0m [\e[32mPASS\e[0m] $@" >&2
}

function fail() {
	echo -e "\e[37m$(date +"%y-%m-%d %H:%M:%S %Z")\e[0m [\e[91mFAIL\e[0m] $@" >&2
}

main
