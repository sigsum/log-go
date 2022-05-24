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
shopt -s nullglob
trap cleanup EXIT

declare -A nodes
declare -A nodes

pri=conf/primary.config
sec=conf/secondary.config

function main() {
	check_go_deps

	node_setup $pri
	node_setup $sec

	nodes[$pri:ssrv_extra_args]="-secondary-url=${nodes[$sec:ssrv_endpoint]}"
	nodes[$pri:ssrv_extra_args]+=" -secondary-pubkey=${nodes[$sec:ssrv_pub]}"
	node_start $pri

	nodes[$sec:ssrv_extra_args]="-primary-url=${nodes[$pri:ssrv_endpoint]}"
	nodes[$sec:ssrv_extra_args]+=" -primary-pubkey=${nodes[$pri:ssrv_pub]}"
	node_start $sec

	client_setup conf/client.config

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

function node_setup() {
	local i=$1; shift
	nodes[$i:log_dir]=$(mktemp -d)
	trillian_setup $i
	sigsum_setup $i
}

function node_start() {
	local i=$1; shift
	trillian_start $i
	sigsum_start $i
}

function trillian_setup() {
	local i=$1; shift
	info "setting up Trillian ($i)"

	source $i
	nodes[$i:tsrv_rpc]=$tsrv_rpc
	nodes[$i:tsrv_http]=$tsrv_http
	nodes[$i:tseq_rpc]=$tseq_rpc
	nodes[$i:tseq_http]=$tseq_http
}

function trillian_start() {
	local i=$1; shift
	info "starting up Trillian ($i)"

	trillian_log_server\
		-rpc_endpoint=${nodes[$i:tsrv_rpc]}\
		-http_endpoint=${nodes[$i:tsrv_http]}\
		-log_dir=${nodes[$i:log_dir]} 2>/dev/null &
	nodes[$i:tsrv_pid]=$!
	info "started Trillian log server (pid ${nodes[$i:tsrv_pid]})"

	trillian_log_signer\
		-force_master\
		-rpc_endpoint=${nodes[$i:tseq_rpc]}\
		-http_endpoint=${nodes[$i:tseq_http]}\
		-log_dir=${nodes[$i:log_dir]} 2>/dev/null &
	nodes[$i:tseq_pid]=$!
	info "started Trillian log sequencer (pid ${nodes[$i:tseq_pid]})"

	nodes[$i:ssrv_tree_id]=$(createtree --admin_server ${nodes[$i:tsrv_rpc]} 2>/dev/null)
	[[ $? -eq 0 ]] ||
		die "must provision a new Merkle tree"

	info "provisioned Merkle tree with id ${nodes[$i:ssrv_tree_id]}"
}

function sigsum_setup() {
	local i=$1; shift
	info "setting up Sigsum server ($i)"
	source $i

	nodes[$i:ssrv_role]=$ssrv_role
	nodes[$i:ssrv_endpoint]=$ssrv_endpoint
	nodes[$i:ssrv_prefix]=$ssrv_prefix
	nodes[$i:ssrv_shard_start]=$ssrv_shard_start
	nodes[$i:ssrv_interval]=$ssrv_interval
	nodes[$i:log_url]=${nodes[$i:ssrv_endpoint]}/${nodes[$i:ssrv_prefix]}/sigsum/v0

	nodes[$i:wit1_priv]=$(sigsum-debug key private)
	nodes[$i:wit1_pub]=$(echo ${nodes[$i:wit1_priv]} | sigsum-debug key public)
	nodes[$i:wit1_key_hash]=$(echo ${nodes[$i:wit1_pub]} | sigsum-debug key hash)
	nodes[$i:wit2_priv]=$(sigsum-debug key private)
	nodes[$i:wit2_pub]=$(echo ${nodes[$i:wit2_priv]} | sigsum-debug key public)
	nodes[$i:wit2_key_hash]=$(echo ${nodes[$i:wit2_pub]} | sigsum-debug key hash)
	nodes[$i:ssrv_witnesses]=${nodes[$i:wit1_pub]},${nodes[$i:wit2_pub]}

	nodes[$i:ssrv_priv]=$(sigsum-debug key private)
	nodes[$i:ssrv_pub]=$(echo ${nodes[$i:ssrv_priv]} | sigsum-debug key public)
	nodes[$i:ssrv_key_hash]=$(echo ${nodes[$i:ssrv_pub]} | sigsum-debug key hash)
}

function sigsum_start() {
	local i=$1; shift
	info "starting Sigsum log server ($i)"

	sigsum_log_go\
		-prefix=${nodes[$i:ssrv_prefix]}\
		-trillian_id=${nodes[$i:ssrv_tree_id]}\
		-shard_interval_start=${nodes[$i:ssrv_shard_start]}\
		-key=<(echo ${nodes[$i:ssrv_priv]})\
		-witnesses=${nodes[$i:ssrv_witnesses]}\
		-interval=${nodes[$i:ssrv_interval]}\
		-http_endpoint=${nodes[$i:ssrv_endpoint]}\
		-log-color="true"\
		-log-level="debug"\
		-role=${nodes[$i:ssrv_role]} ${nodes[$i:ssrv_extra_args]} \
		-log-file=${nodes[$i:log_dir]}/sigsum-log.log 2>/dev/null &
	nodes[$i:ssrv_pid]=$!

	info "started Sigsum log server on ${nodes[$i:ssrv_endpoint]} (pid ${nodes[$i:ssrv_pid]})"
}

function cleanup() {
	set +e

	info "cleaning up, please wait..."
	sleep 1

	for i in $pri $sec; do
		boundp $i:ssrv_pid && kill -2 ${nodes[$i:ssrv_pid]}
		boundp $i:tseq_pid && kill -2 ${nodes[$i:tseq_pid]}
		while :; do
			sleep 1

			boundp $i:tseq_pid && ps -p ${nodes[$i:tseq_pid]} >/dev/null && continue
			boundp $i:ssrv_pid && ps -p ${nodes[$i:$ssrv_pid]} >/dev/null && continue

			break
		done
	done
	info "stopped Trillian log sequencer(s)"
	info "stopped Sigsum log server(s)"

	for i in $pri $sec; do
		if ! deletetree -admin_server=$tsrv_rpc -log_id=${nodes[$i:ssrv_tree_id]}; then
			warn "failed deleting provisioned Merkle tree ${nodes[$i:ssrv_tree_id]}"
		else
			info "deleted provisioned Merkle tree ${nodes[$i:ssrv_tree_id]}"
		fi
	done

	for i in $pri $sec; do
		boundp $i:tsrv_pid || continue
		kill -2 ${nodes[$i:tsrv_pid]}
		while :; do
			sleep 1

			ps -p ${nodes[$i:tsrv_pid]} >/dev/null && continue

			break
		done
	done
	info "stopped Trillian log server(s)"

	for i in $pri $sec; do
		printf "\n  Press any key to delete logs in ${nodes[$i:log_dir]}"
		read dummy

		rm -rf ${nodes[$i:log_dir]}
	done
}

function check_setup() {
	for i in $pri $sec; do
		sleep 3

		ps -p ${nodes[$i:tseq_pid]} >/dev/null || die "must have Trillian log sequencer ($i)"
		ps -p ${nodes[$i:tsrv_pid]} >/dev/null || die "must have Trillian log server ($i)"
		ps -p ${nodes[$i:ssrv_pid]} >/dev/null || die "must have Sigsum log server ($i)"
	done
}

function run_tests() {
	num_leaf=5

	test_signed_tree_head 0
	for i in $(seq 1 $num_leaf); do
		test_add_leaf $i
	done

	info "waiting for $num_leaf leaves to be merged..."
	sleep ${nodes[$pri:ssrv_interval]::-1}

	test_signed_tree_head $num_leaf
	for i in $(seq 1 $(( $num_leaf - 1 ))); do
		test_consistency_proof $i $num_leaf
	done

	test_cosignature ${nodes[$pri:wit1_key_hash]} ${nodes[$pri:wit1_priv]}
	test_cosignature ${nodes[$pri:wit2_key_hash]} ${nodes[$pri:wit2_priv]}

	info "waiting for cosignature to be available..."
	sleep ${nodes[$pri:ssrv_interval]::-1}

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
	local log_dir=${nodes[$pri:log_dir]}
	desc="GET tree-head-to-cosign (tree size $1)"
	curl -s -w "%{http_code}" ${nodes[$pri:log_url]}/get-tree-head-to-cosign \
		>$log_dir/rsp

	if [[ $(status_code $pri) != 200 ]]; then
		fail "$desc: http status code $(status_code $pri)"
		return
	fi

	if ! keys $pri "timestamp" "tree_size" "root_hash" "signature"; then
		fail "$desc: ascii keys in response $(debug_response $pri)"
		return
	fi

	now=$(date +%s)
	if [[ $(value_of $pri "timestamp") -gt $now ]]; then
		fail "$desc: timestamp $(value_of $pri "timestamp") is too large"
		return
	fi
	if [[ $(value_of $pri "timestamp") -lt $(( $now - ${nodes[$pri:ssrv_interval]::-1} )) ]]; then
		fail "$desc: timestamp $(value_of $pri "timestamp") is too small"
		return
	fi

	if [[ $(value_of $pri "tree_size") != $1 ]]; then
		fail "$desc: tree size $(value_of $pri "tree_size")"
		return
	fi

	# TODO: verify tree head signature
	pass $desc
}

function test_cosigned_tree_head() {
	local log_dir=${nodes[$pri:log_dir]}
	desc="GET get-tree-head-cosigned (all witnesses)"
	curl -s -w "%{http_code}" ${nodes[$pri:log_url]}/get-tree-head-cosigned \
		>$log_dir/rsp

	if [[ $(status_code $pri) != 200 ]]; then
		fail "$desc: http status code $(status_code $pri)"
		return
	fi

	if ! keys $pri "timestamp" "tree_size" "root_hash" "signature" "cosignature" "key_hash"; then
		fail "$desc: ascii keys in response $(debug_response $pri)"
		return
	fi

	now=$(date +%s)
	if [[ $(value_of $pri "timestamp") -gt $now ]]; then
		fail "$desc: timestamp $(value_of $pri "timestamp") is too large"
		return
	fi
	if [[ $(value_of $pri "timestamp") -lt $(( $now - ${nodes[$pri:ssrv_interval]::-1} * 2 )) ]]; then
		fail "$desc: timestamp $(value_of $pri "timestamp") is too small"
		return
	fi

	if [[ $(value_of $pri "tree_size") != $1 ]]; then
		fail "$desc: tree size $(value_of $pri "tree_size")"
		return
	fi

	for got in $(value_of $pri key_hash); do
		found=""
		for want in ${nodes[$pri:wit1_key_hash]} ${nodes[$pri:wit2_key_hash]}; do
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
	local log_dir=${nodes[$pri:log_dir]}
	desc="GET get-inclusion-proof (tree_size $1, data \"$2\", index $3)"
	signature=$(echo $2 | sigsum-debug leaf sign -k $cli_priv -h ${nodes[$pri:ssrv_shard_start]})
	leaf_hash=$(echo $2 | sigsum-debug leaf hash -k $cli_key_hash -s $signature -h ${nodes[$pri:ssrv_shard_start]})
	curl -s -w "%{http_code}" ${nodes[$pri:log_url]}/get-inclusion-proof/$1/$leaf_hash >$log_dir/rsp

	if [[ $(status_code $pri) != 200 ]]; then
		fail "$desc: http status code $(status_code $pri)"
		return
	fi

	if ! keys $pri "leaf_index" "inclusion_path"; then
		fail "$desc: ascii keys in response $(debug_response $pri)"
		return
	fi

	if [[ $(value_of $pri leaf_index) != $3 ]]; then
		fail "$desc: wrong leaf index $(value_of $pri leaf_index)"
		return
	fi

	# TODO: verify inclusion proof
	pass $desc
}

function test_consistency_proof() {
	local log_dir=${nodes[$pri:log_dir]}
	desc="GET get-consistency-proof (old_size $1, new_size $2)"
	curl -s -w "%{http_code}" ${nodes[$pri:log_url]}/get-consistency-proof/$1/$2 >$log_dir/rsp

	if [[ $(status_code $pri) != 200 ]]; then
		fail "$desc: http status code $(status_code $pri)"
		return
	fi

	if ! keys $pri "consistency_path"; then
		fail "$desc: ascii keys in response $(debug_response $pri)"
		return
	fi

	# TODO: verify consistency proof
	pass $desc
}

function test_get_leaf() {
	local log_dir=${nodes[$pri:log_dir]}
	desc="GET get-leaves (data \"$1\", index $2)"
	curl -s -w "%{http_code}" ${nodes[$pri:log_url]}/get-leaves/$2/$2 >$log_dir/rsp

	if [[ $(status_code $pri) != 200 ]]; then
		fail "$desc: http status code $(status_code $pri)"
		return
	fi

	if ! keys $pri "shard_hint" "checksum" "signature" "key_hash"; then
		fail "$desc: ascii keys in response $(debug_response $pri)"
		return
	fi

	if [[ $(value_of $pri shard_hint) != ${nodes[$pri:ssrv_shard_start]} ]]; then
		fail "$desc: wrong shard hint $(value_of $pri shard_hint)"
		return
	fi

	message=$(openssl dgst -binary <(echo $1) | base16)
	checksum=$(openssl dgst -binary <(echo $message | base16 -d) | base16)
	if [[ $(value_of $pri checksum) != $checksum ]]; then
		fail "$desc: wrong checksum $(value_of $pri checksum)"
		return
	fi

	if [[ $(value_of $pri key_hash) != $cli_key_hash ]]; then
		fail "$desc: wrong key hash $(value_of $pri key_hash)"
	fi

	# TODO: check leaf signature
	pass $desc
}

function test_add_leaf() {
	local log_dir=${nodes[$pri:log_dir]}
	desc="POST add-leaf (data \"$1\")"
	echo "shard_hint=${nodes[$pri:ssrv_shard_start]}" > $log_dir/req
	echo "message=$(openssl dgst -binary <(echo $1) | base16)" >> $log_dir/req
	echo "signature=$(echo $1 |
		sigsum-debug leaf sign -k $cli_priv -h ${nodes[$pri:ssrv_shard_start]})" >> $log_dir/req
	echo "public_key=$cli_pub" >> $log_dir/req
	echo "domain_hint=$cli_domain_hint" >> $log_dir/req
	cat $log_dir/req |
		curl -s -w "%{http_code}" --data-binary @- ${nodes[$pri:log_url]}/add-leaf \
		>$log_dir/rsp

	if [[ $(status_code $pri) != 200 ]]; then
		fail "$desc: http status code $(status_code $pri)"
		return
	fi

	if ! keys $pri; then
		fail "$desc: ascii keys in response $(debug_response $pri)"
		return
	fi

	pass $desc
}

function test_cosignature() {
	local log_dir=${nodes[$pri:log_dir]}
	#local log_url=${nodes[$pri:log_url]}
	#local ssrv_key_hash=${nodes[$pri:ssrv_key_hash]}
	desc="POST add-cosignature (witness $1)"
	echo "key_hash=$1" > $log_dir/req
	echo "cosignature=$(curl -s ${nodes[$pri:log_url]}/get-tree-head-to-cosign |
		sigsum-debug head sign -k $2 -h ${nodes[$pri:ssrv_key_hash]})" >> $log_dir/req
	cat $log_dir/req |
		curl -s -w "%{http_code}" --data-binary @- ${nodes[$pri:log_url]}/add-cosignature \
		>$log_dir/rsp

	if [[ $(status_code $pri) != 200 ]]; then
		fail "$desc: http status code $(status_code $pri)"
		return
	fi

	if ! keys $pri; then
		fail "$desc: ascii keys in response $(debug_response $pri)"
		return
	fi

	pass $desc
}

function debug_response() {
	local i=$1; shift
	echo ""
	cat ${nodes[$i:log_dir]}/rsp
}

function status_code() {
	local i=$1; shift
	tail -n1 ${nodes[$i:log_dir]}/rsp
}

function value_of() {
	local i=$1; shift
	while read line; do
		key=$(echo $line | cut -d"=" -f1)
		if [[ $key != $1 ]]; then
			continue
		fi

		value=$(echo $line | cut -d"=" -f2)
		echo $value
	done < <(head --lines=-1 ${nodes[$i:log_dir]}/rsp)
}

function keys() {
        local i=$1; shift
	declare -A map
	map[thedummystring]=to_avoid_error_on_size_zero
	while read line; do
		key=$(echo $line | cut -d"=" -f1)
		map[$key]=ok
	done < <(head --lines=-1 ${nodes[$i:log_dir]}/rsp)

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

function boundp {
    [[ ${!nodes[@]} == *$1* ]] && return 1
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
