#!/bin/bash

#
# Requirements to run
#
#   - Install required dependencies, see check_go_deps()
#   - Fill in the empty values in conf/client.config
#
# Example usage:
#
#     $ ./test.sh
#

set -eu
shopt -s nullglob
trap cleanup EXIT

declare g_offline_mode=1

declare -A nvars
declare nodes="loga logb"
declare -r loga=conf/primary.config
declare -r logb=conf/secondary.config
declare -r logc=conf/logc.config
declare -r client=conf/client.config
declare -r mysql_uri="${MYSQL_URI:-sigsum_test:zaphod@tcp(127.0.0.1:3306)/sigsum_test}"

# Set based on --extended / --ephemeral options
testflavor=basic

function main() {
	while [[ $# > 0 ]] ; do
		case $1 in
			--extended)
				testflavor=extended
				;;
			--ephemeral)
				testflavor=ephemeral
				;;
			*)
				die "Unknown option: $1"
				;;
		esac
		shift
	done
	check_go_deps

	node_setup $loga $logb

	# Primary
	nvars[$loga:ssrv_extra_args]="-secondary-url=http://${nvars[$logb:int_url]}"
	nvars[$loga:ssrv_extra_args]+=" -secondary-pubkey=$(cat ${nvars[$logb:log_dir]}/ssrv.key.pub)"
	nvars[$loga:ssrv_extra_args]+=" -rate-limit-config=rate-limit.cfg"
	nvars[$loga:ssrv_extra_args]+=" -allow-test-domain=true"
	if [[ "$testflavor" = ephemeral ]] ; then
		nvars[$loga:ssrv_extra_args]+=" -ephemeral-test-backend"
	fi
	node_start $loga

	# Secondary
	nvars[$logb:ssrv_extra_args]="-primary-url=http://${nvars[$loga:int_url]}"
	nvars[$logb:ssrv_extra_args]+=" -primary-pubkey=$(cat ${nvars[$loga:log_dir]}/ssrv.key.pub)"
	if [[ "$testflavor" = ephemeral ]] ; then
		nvars[$logb:ssrv_extra_args]+=" -ephemeral-test-backend"
	fi
	node_start $logb

        # Wait a bit to give time to the logs to be ready
        sleep 10

	client_setup $client
	check_setup $loga $logb
	run_tests $loga $logb $client 0 5
	run_tests $loga $logb $client 5 1

	if [[ $testflavor == extended ]]; then
		# for tree equality tests later on; FIXME: remove
		test_signed_tree_head $loga 6
		cp ${nvars[$loga:log_dir]}/rsp ${nvars[$loga:log_dir]}/last_sth

		node_stop_fe $loga $logb
		node_destroy $loga; node_stop_be $loga
		node_setup $logc

		node_promote $logb $loga
		nvars[$logb:ssrv_extra_args]="-secondary-url=http://${nvars[$logc:int_url]}"
		nvars[$logb:ssrv_extra_args]+=" -secondary-pubkey=$(cat ${nvars[$logc:log_dir]}/ssrv.key.pub)"
		node_start_fe $logb

		nvars[$logc:ssrv_extra_args]="-primary-url=http://${nvars[$logb:int_url]}"
		nvars[$logc:ssrv_extra_args]+=" -primary-pubkey=$(cat ${nvars[$logb:log_dir]}/ssrv.key.pub)"
		nodes+=" logc"
		node_start $logc

		check_setup $logb $logc
		run_tests_extended $logb $logc $client 6 ${nvars[$loga:log_dir]}/last_sth
	fi
}

function check_go_deps() {
	if [[ "$testflavor" != ephemeral ]] ; then
		[[ $(command -v trillian_log_signer)  ]] || die "Hint: go install github.com/google/trillian/cmd/trillian_log_signer"
		[[ $(command -v trillian_log_server)  ]] || die "Hint: go install github.com/google/trillian/cmd/trillian_log_server"
		[[ $(command -v createtree)           ]] || die "Hint: go install github.com/google/trillian/cmd/createtree"
		[[ $(command -v deletetree)           ]] || die "Hint: go install github.com/google/trillian/cmd/deletetree"
		[[ $(command -v updatetree)           ]] || die "Hint: go install github.com/google/trillian/cmd/updatetree"
	fi
	go build -o sigsum-debug sigsum.org/sigsum-go/cmd/sigsum-debug
}

function client_setup() {
	for i in $@; do
		info "setting up client ($i)"
		local dir=$(mktemp -d /tmp/sigsum-log-test.XXXXXXXXXX)
		info "$i: logging to $dir"
		nvars[$i:log_dir]=$dir
		if [[ -f $i ]];
		then
			source $i
			echo $cli_priv > ${nvars[$i:log_dir]}/cli.key
		else
			./sigsum-debug key private > ${nvars[$i:log_dir]}/cli.key
		fi
		./sigsum-debug key public < ${nvars[$i:log_dir]}/cli.key > ${nvars[$i:log_dir]}/cli.key.pub
		nvars[$i:cli_key_hash]=$(cat ${nvars[$i:log_dir]}/cli.key.pub | ./sigsum-debug key hash)
	done
}

function node_setup() {
	for i in $@; do
		local dir=$(mktemp -d /tmp/sigsum-log-test.XXXXXXXXXX)
		info "$i: logging to $dir"
		nvars[$i:log_dir]=$dir
		if [[ "$testflavor" != ephemeral ]] ; then
			trillian_setup $i
		fi
		sigsum_setup $i
	done
}

# node_start starts trillian and sigsum and creates new trees
function node_start() {
	for i in $@; do
		if [[ "$testflavor" != ephemeral ]] ; then
			trillian_start $i
		fi
		sigsum_create_tree $i
		sigsum_start $i
	done
}

# node_start_* starts sequencer and sigsum but does not create new trees
function node_start_fe() {
	if [[ "$testflavor" != ephemeral ]] ; then
		trillian_start_sequencer $@
	fi
	sigsum_start $@
}

function node_promote() {
	local new_primary=$1; shift
	local prev_primary=$1; shift
	[[ ${nvars[$new_primary:ssrv_role]} == secondary ]] || die "$new_primary: not a secondary node"
	[[ ${nvars[$prev_primary:ssrv_role]} == primary ]] || die "$prev_primary: not the primary node"

	info "promoting secondary node to primary ($new_primary)"
	local srv=${nvars[$new_primary:tsrv_rpc]}
	local tree_id=${nvars[$new_primary:ssrv_tree_id]}

	# NOTE: updatetree doesn't seem to exit with !=0 when failing
	# TODO: try combining the first two invocations into one
	[[ $(updatetree --admin_server $srv -tree_id $tree_id -tree_state FROZEN -logtostderr 2>/dev/null) == FROZEN ]] || \
		die "unable to freeze tree $tree_id"
	[[ $(updatetree --admin_server $srv -tree_id $tree_id -tree_type LOG     -logtostderr 2>/dev/null) == FROZEN ]] || \
		die "unable to change tree type to LOG for tree $tree_id"
	[[ $(updatetree --admin_server $srv -tree_id $tree_id -tree_state ACTIVE -logtostderr 2>/dev/null) == ACTIVE ]] || \
		die "unable to unfreeze tree $tree_id"
	info "tree $tree_id type changed from PREORDERED_LOG to LOG"

	nvars[$new_primary:ssrv_role]=primary
	nvars[$new_primary:ssrv_interval]=5 # FIXME: parameterize

	info "copying key files"
	mv ${nvars[$prev_primary:log_dir]}/ssrv.key ${nvars[$new_primary:log_dir]}/ssrv.key
	mv ${nvars[$prev_primary:log_dir]}/ssrv.key.pub ${nvars[$new_primary:log_dir]}/ssrv.key.pub
	nvars[$new_primary:ssrv_key_hash]=${nvars[$prev_primary:ssrv_key_hash]}
	nvars[$new_primary:token]=${nvars[$prev_primary:token]}

	info "moving sth-store file"
	mv ${nvars[$prev_primary:log_dir]}/sth-store ${nvars[$new_primary:log_dir]}/sth-store
}

function trillian_setup() {
	for i in $@; do
		info "setting up Trillian ($i)"

		source $i
		nvars[$i:tsrv_rpc]=$tsrv_rpc
		nvars[$i:tsrv_http]=$tsrv_http
		nvars[$i:tseq_rpc]=$tseq_rpc
		nvars[$i:tseq_http]=$tseq_http
	done
}

# trillian_start starts trillian components and creates new trees
function trillian_start() {
	trillian_start_server $@
	trillian_start_sequencer $@
	trillian_createtree $@
}

function trillian_start_server() {
	for i in $@; do
		info "starting up Trillian server ($i)"

		trillian_log_server\
			-mysql_uri=${mysql_uri}\
			-rpc_endpoint=${nvars[$i:tsrv_rpc]}\
			-http_endpoint=${nvars[$i:tsrv_http]}\
			-log_dir=${nvars[$i:log_dir]} 2>/dev/null &
		nvars[$i:tsrv_pid]=$!
		info "started Trillian log server (pid ${nvars[$i:tsrv_pid]})"
	done
}

function trillian_start_sequencer() {
	for i in $@; do
		# no sequencer needed for secondaries
		[[ ${nvars[$i:ssrv_role]} == secondary ]] && continue

		info "starting up Trillian sequencer ($i)"
		trillian_log_signer\
			-force_master\
			-mysql_uri=${mysql_uri}\
			-rpc_endpoint=${nvars[$i:tseq_rpc]}\
			-http_endpoint=${nvars[$i:tseq_http]}\
			-log_dir=${nvars[$i:log_dir]} 2>/dev/null &
		nvars[$i:tseq_pid]=$!
		info "started Trillian log sequencer (pid ${nvars[$i:tseq_pid]})"
	done
}

function trillian_createtree() {
	for i in $@; do
		local createtree_extra_args=""

		[[ ${nvars[$i:ssrv_role]} == secondary ]] && createtree_extra_args=" -tree_type PREORDERED_LOG"
		nvars[$i:ssrv_tree_id]=$(createtree --admin_server ${nvars[$i:tsrv_rpc]} $createtree_extra_args -logtostderr 2>/dev/null)
		[[ $? -eq 0 ]] || die "must provision a new Merkle tree"

		info "provisioned Merkle tree with id ${nvars[$i:ssrv_tree_id]}"
	done
}

function sigsum_setup() {
	for i in $@; do
		info "setting up Sigsum server ($i)"
		source $i

		nvars[$i:ssrv_role]=$ssrv_role
		nvars[$i:ssrv_endpoint]=$ssrv_endpoint
		nvars[$i:ssrv_internal]=$ssrv_internal
		nvars[$i:ssrv_prefix]=$ssrv_prefix
		nvars[$i:ssrv_interval]=$ssrv_interval_sec


		nvars[$i:log_url]=${nvars[$i:ssrv_endpoint]}/${nvars[$i:ssrv_prefix]}
		nvars[$i:int_url]=${nvars[$i:ssrv_internal]}/${nvars[$i:ssrv_prefix]}

		./sigsum-debug key private | tee ${nvars[$i:log_dir]}/wit1.key \
			| ./sigsum-debug key public > ${nvars[$i:log_dir]}/wit1.key.pub
		nvars[$i:wit1_key_hash]=$(./sigsum-debug key hash < ${nvars[$i:log_dir]}/wit1.key.pub)

		./sigsum-debug key private | tee ${nvars[$i:log_dir]}/wit2.key \
			| ./sigsum-debug key public > ${nvars[$i:log_dir]}/wit2.key.pub
		nvars[$i:wit2_key_hash]=$(./sigsum-debug key hash < ${nvars[$i:log_dir]}/wit2.key.pub)

		nvars[$i:ssrv_witnesses]=$(cat ${nvars[$i:log_dir]}/wit1.key.pub),$(cat ${nvars[$i:log_dir]}/wit2.key.pub)

		./sigsum-debug key private | tee ${nvars[$i:log_dir]}/ssrv.key \
			| ./sigsum-debug key public > ${nvars[$i:log_dir]}/ssrv.key.pub
		nvars[$i:ssrv_key_hash]=$(cat ${nvars[$i:log_dir]}/ssrv.key.pub | ./sigsum-debug key hash)
		# Use special test.sigsum.org test key to generate token.
		nvars[$i:token]=$(echo 0000000000000000000000000000000000000000000000000000000000000001 \
				    | ./sigsum-debug token $(cat ${nvars[$i:log_dir]}/ssrv.key.pub))
	done
}

function sigsum_create_tree() {
	for i in $@; do
		if [[ ${nvars[$i:ssrv_role]} = primary ]] ; then
			info "creating empty ${nvars[$i:log_dir]}/sth-store"
			go run ../cmd/sigsum-mktree \
			   -sth-path=${nvars[$i:log_dir]}/sth-store \
			   -key=${nvars[$i:log_dir]}/ssrv.key
		fi
	done
}

function sigsum_start() {
	for i in $@; do
		local role=${nvars[$i:ssrv_role]}
		local binary=sigsum-log-primary;
		local extra_args="${nvars[$i:ssrv_extra_args]}"

		if [[ $role = primary ]]; then
			extra_args+=" -witnesses=${nvars[$i:ssrv_witnesses]}"
			extra_args+=" -sth-path=${nvars[$i:log_dir]}/sth-store"
		else
			binary=sigsum-log-secondary
		fi
		if [[ "$testflavor" = ephemeral ]] ; then
			extra_args+=" -ephemeral-test-backend"
		else
			extra_args+=" -trillian-rpc-server=${nvars[$i:tsrv_rpc]}"
			extra_args+=" -tree-id=${nvars[$i:ssrv_tree_id]}"
		fi

		info "starting Sigsum log $role node ($i)"

		args="$extra_args \
                      -url-prefix=${nvars[$i:ssrv_prefix]} \
		      -interval=${nvars[$i:ssrv_interval]}s \
		      -external-endpoint=${nvars[$i:ssrv_endpoint]} \
		      -internal-endpoint=${nvars[$i:ssrv_internal]} \
		      -log-level=debug \
		      -log-file=${nvars[$i:log_dir]}/sigsum-log.log"
		# Can't use go run, because then we don't get the right pid to kill for cleanup.
		go build -o $binary ../cmd/$binary/main.go
		./$binary $args -key=${nvars[$i:log_dir]}/ssrv.key \
			2>${nvars[$i:log_dir]}/sigsum-log.$(date +%s).stderr &
		nvars[$i:ssrv_pid]=$!

		info "started Sigsum log server on ${nvars[$i:ssrv_endpoint]} / ${nvars[$i:ssrv_internal]} (pid ${nvars[$i:ssrv_pid]})"
	done
}

function node_stop() {
	node_stop_fe $@
	node_stop_be $@
}

# Delete log tree for, requires trillian server ("backend") to be running
function node_destroy() {
	if [[ "$testflavor" != ephemeral ]] ; then
		for i in $@; do
			if ! deletetree -admin_server=$tsrv_rpc -log_id=${nvars[$i:ssrv_tree_id]} -logtostderr 2>/dev/null; then
				warn "failed deleting provisioned Merkle tree ${nvars[$i:ssrv_tree_id]}"
			else
				info "deleted provisioned Merkle tree ${nvars[$i:ssrv_tree_id]}"
			fi
		done
	fi
}

function node_stop_fe() {
	for i in $@; do

		[[ -v nvars[$i:ssrv_pid] ]] && pp ${nvars[$i:ssrv_pid]} && kill ${nvars[$i:ssrv_pid]} # FIXME: why is SIGINT (often) not enough?
		if [[ "$testflavor" != ephemeral ]] ; then
			[[ -v nvars[$i:tseq_pid] ]] && pp ${nvars[$i:tseq_pid]} && kill -2 ${nvars[$i:tseq_pid]}
			while :; do
				sleep 1

				[[ -v nvars[$i:tseq_pid] ]] && pp ${nvars[$i:tseq_pid]} && continue
				[[ -v nvars[$i:ssrv_pid] ]] && pp ${nvars[$i:ssrv_pid]} && continue

				break
			done
			info "stopped Trillian log sequencer ($i)"
		fi
		info "stopped Sigsum log server ($i)"

	done
}

function node_stop_be() {
	if [[ "$testflavor" != ephemeral ]] ; then
		for i in $@; do
			pp ${nvars[$i:tsrv_pid]} && kill ${nvars[$i:tsrv_pid]}
			while :; do
				sleep 1

				# The Trillian log server doesn't exit
				# properly on first SIGTERM, so we repeat it,
				# rather than just waiting for the process to
				# shut down.
				if pp ${nvars[$i:tsrv_pid]}; then
					info "Resending SIGTERM to process ${nvars[$i:tsrv_pid]}"
					kill ${nvars[$i:tsrv_pid]}
					continue
				fi

				break
			done
			info "stopped Trillian log server ($i)"
		done
	fi
}

function cleanup() {
	set +e

	info "cleaning up, please wait..."

	for var in $nodes; do
		declare -n cleanup_i=$var # Using unique iterator name, bc leaking
		node_stop_fe $cleanup_i
	done

	for var in $nodes; do
		declare -n cleanup_i=$var # Using unique iterator name, bc leaking
		node_destroy $cleanup_i
	done

	for var in $nodes; do
		declare -n cleanup_i=$var # Using unique iterator name, bc leaking
		node_stop_be $cleanup_i
	done

	for var in $nodes; do
		declare -n cleanup_i=$var # Using unique iterator name, bc leaking
		printf "\n  Press enter to delete logs in ${nvars[$cleanup_i:log_dir]}"
		read dummy

		rm -rf ${nvars[$cleanup_i:log_dir]}
	done
}

function check_setup() {
	sleep 3
	for i in $@; do
		info "checking setup for $i"
		if [[ "$testflavor" != ephemeral ]] ; then
			if [[ ${nvars[$i:ssrv_role]} == primary ]]; then
				[[ -v nvars[$i:tseq_pid] ]] && pp ${nvars[$i:tseq_pid]} || die "must have Trillian log sequencer ($i)"
			fi
			[[ -v nvars[$i:tsrv_pid] ]] && pp ${nvars[$i:tsrv_pid]} || die "must have Trillian log server ($i)"
		fi
		[[ -v nvars[$i:ssrv_pid] ]] && pp ${nvars[$i:ssrv_pid]} || die "must have Sigsum log server ($i)"
	done
}

function run_tests() {
	local pri=$1; shift
	local sec=$1; shift
	local cli=$1; shift
	local start_leaf=$1; shift # 0-based
	local num_leaf=$1; shift

	info "running ordinary tests, pri=$pri, start_leaf=$start_leaf, num_leaf=$num_leaf"

	test_signed_tree_head $pri $start_leaf

	info "adding $num_leaf leaves"
	test_add_leaves $pri $cli $(( $start_leaf + 1 )) $num_leaf
	num_leaf=$(( $num_leaf + $start_leaf ))

	test_signed_tree_head $pri $num_leaf
	for i in $(seq $(( $start_leaf + 1 )) $(( $num_leaf - 1 ))); do
		test_consistency_proof $pri $i $num_leaf
	done

	test_cosignature $pri ${nvars[$pri:wit1_key_hash]} ${nvars[$pri:log_dir]}/wit1.key
	test_cosignature $pri ${nvars[$pri:wit2_key_hash]} ${nvars[$pri:log_dir]}/wit2.key

	info "waiting for cosignature(s) to be available..."
	sleep ${nvars[$pri:ssrv_interval]}

	test_cosigned_tree_head $pri $num_leaf
	for i in $(seq  $(( $start_leaf + 1 )) $num_leaf); do
		test_inclusion_proof $pri $cli $num_leaf $i $(( $i - 1 ))
	done

	for i in $(seq  $(( $start_leaf + 1 )) $num_leaf); do
		test_get_leaf $pri $cli $i $(( $i - 1 ))
	done

	warn "no signatures and merkle proofs were verified"
}

run_tests_extended() {
	local pri=$1; shift
	local sec=$1; shift
	local cli=$1; shift
	local current_size=$1; shift
	local old_pri_sth_rsp=$1; shift
	info "running extended tests"

	info "wait for new primary and secondary to catch up and merge"
	sleep $(( ${nvars[$pri:ssrv_interval]} + ${nvars[$sec:ssrv_interval]} + 1 ))

	test_signed_tree_head $pri $current_size
	test_tree_heads_equal ${nvars[$pri:log_dir]}/rsp $old_pri_sth_rsp

	run_tests $pri $sec $cli $current_size 5
}

function test_signed_tree_head() {
	local pri=$1; shift
	local size=$1; shift
	local log_dir=${nvars[$pri:log_dir]}
	local desc="GET get-next-tree-head (size $size)"

	curl -s -w "%{http_code}" ${nvars[$pri:log_url]}/get-next-tree-head \
	     >$log_dir/rsp

	if [[ $(status_code $pri) != 200 ]]; then
		fail "$desc: http status code $(status_code $pri)"
		return
	fi

	if ! keys $pri "size" "root_hash" "signature"; then
		fail "$desc: ascii keys in response $(debug_response $pri)"
		return
	fi

	if [[ $(value_of $pri "size") != $size ]]; then
		fail "$desc: size $(value_of $pri "size")"
		return
	fi

	# TODO: verify tree head signature
	pass $desc
}

function test_tree_heads_equal() {
	local rsp1=$1; shift
	local rsp2=$1; shift
	local desc="comparing tree heads ($rsp1, $rsp2)"

	n1_size=$(value_of_file $rsp1 "size")
	n2_size=$(value_of_file $rsp2 "size")
	if [[ $n1_size -ne $n2_size ]]; then
		fail "$desc: size: $n1_size != $n2_size"
		return
	fi

	n1_root_hash=$(value_of_file $rsp1 "root_hash")
	n2_root_hash=$(value_of_file $rsp2 "root_hash")
	if [[ $n1_root_hash != $n2_root_hash ]]; then
		fail "$desc: root_hash: $n1_root_hash != $n2_root_hash"
		return
	fi

	pass $desc
}

function test_cosigned_tree_head() {
	local pri=$1; shift
	local size=$1; shift
	local log_dir=${nvars[$pri:log_dir]}
	local desc="GET get-tree-head (all witnesses), size $size"

	curl -s -w "%{http_code}" ${nvars[$pri:log_url]}/get-tree-head \
	     >$log_dir/rsp

	if [[ $(status_code $pri) != 200 ]]; then
		fail "$desc: http status code $(status_code $pri)"
		return
	fi

	if ! keys $pri "size" "root_hash" "signature" "cosignature"; then
		fail "$desc: ascii keys in response $(debug_response $pri)"
		return
	fi

	now=$(date +%s)

	if [[ $(value_of $pri "size") != $size ]]; then
		fail "$desc: size $(value_of $pri "size")"
		return
	fi

	while read cs ; do
		# Check key hash
		found=""
	        got=$(echo $cs | cut -d' ' -f1)
		for want in ${nvars[$pri:wit1_key_hash]} ${nvars[$pri:wit2_key_hash]}; do
			if [[ $got == $want ]]; then
				found=true
			fi
		done

		if [[ -z $found ]]; then
			fail "$desc: missing witness $got"
			return
		fi

		# Check timestamp
		ts=$(echo $cs | cut -d' ' -f2)
		if [[ $ts -gt $now ]]; then
			fail "$desc: timestamp $(value_of $pri "timestamp") is too large"
			return
		fi
		if [[ $ts -lt $(( $now - ${nvars[$pri:ssrv_interval]} * 2 )) ]]; then
			fail "$desc: timestamp $(value_of $pri "timestamp") is too small"
			return
		fi
	done < <(value_of $pri cosignature)

	# TODO: verify tree head signature
	# TODO: verify tree head cosignatures
	pass $desc
}

function test_inclusion_proof() {
	local pri=$1; shift
	local cli=$1; shift
	local size=$1; shift
	local data=$1; shift
	local index=$1; shift
	local log_dir=${nvars[$pri:log_dir]}
	local desc="GET get-inclusion-proof (size $size, data \"$data\", index $index)"

	local signature=$(echo ${data} | ./sigsum-debug leaf sign -k $(cat ${nvars[$cli:log_dir]}/cli.key))
	local leaf_hash=$(echo ${data} | ./sigsum-debug leaf hash -k ${nvars[$cli:cli_key_hash]} -s $signature)
	curl -s -w "%{http_code}" ${nvars[$pri:log_url]}/get-inclusion-proof/${size}/${leaf_hash} >${log_dir}/rsp

	if [[ $(status_code $pri) != 200 ]]; then
		fail "$desc: http status code $(status_code $pri)"
		return
	fi

	if ! keys $pri "leaf_index" "node_hash"; then
		fail "$desc: ascii keys in response $(debug_response $pri)"
		return
	fi

	if [[ $(value_of $pri leaf_index) != ${index} ]]; then
		fail "$desc: wrong leaf index $(value_of $pri leaf_index)"
		return
	fi

	# TODO: verify inclusion proof
	pass $desc
}

function test_consistency_proof() {
	local pri=$1; shift
	local log_dir=${nvars[$pri:log_dir]}
	local desc="GET get-consistency-proof (old_size $1, new_size $2)"

	curl -s -w "%{http_code}" ${nvars[$pri:log_url]}/get-consistency-proof/$1/$2 >$log_dir/rsp

	if [[ $(status_code $pri) != 200 ]]; then
		fail "$desc: http status code $(status_code $pri)"
		return
	fi

	if ! keys $pri "node_hash"; then
		fail "$desc: ascii keys in response $(debug_response $pri)"
		return
	fi

	# TODO: verify consistency proof
	pass $desc
}

function test_get_leaf() {
	local pri=$1; shift	
	local cli=$1; shift	
	local data="$1"; shift
	local index="$1"; shift
	local log_dir=${nvars[$pri:log_dir]}
	local desc="GET get-leaves (data \"$data\", index $index)"

	curl -s -w "%{http_code}" ${nvars[$pri:log_url]}/get-leaves/$index/$((index + 1)) >$log_dir/rsp

	if [[ $(status_code $pri) != 200 ]]; then
		fail "$desc: http status code $(status_code $pri)"
		return
	fi

	if ! keys $pri "leaf"; then
		fail "$desc: ascii keys in response $(debug_response $pri)"
		return
	fi

	local message=$(openssl dgst -binary <(echo $data) | b16encode)
	local checksum=$(openssl dgst -binary <(echo $message | b16decode) | b16encode)
	if [[ $(value_of $pri leaf | cut -d' ' -f1) != $checksum ]]; then
		fail "$desc: wrong checksum $(value_of $pri checksum)"
		return
	fi

	if [[ $(value_of $pri leaf | cut -d' ' -f3) != ${nvars[$cli:cli_key_hash]} ]]; then
		fail "$desc: wrong key hash $(value_of $pri key_hash)"
	fi

	# TODO: check leaf signature
	pass $desc
}

function test_add_leaves() {
	local s=$1; shift
	local cli=$1; shift
	local start=$1; shift	# integer, used as data and filename under subs/
	local end=$(( $start + $1 - 1 )); shift # number of leaves to add
	local desc="add leaves"
	local log_dir=${nvars[$s:log_dir]}
	[[ -d $log_dir/subs/$s ]] || mkdir -p $log_dir/subs/$s

	local -a rc
	for i in $(seq $start $end); do
		rc[$i]=$(add_leaf $s $cli $i)
	done

	# TODO: bail out and fail after $timeout seconds
	while true; do
		local keep_going=0
		for i in $(seq $start $end); do
			if [[ ${rc[$i]} -eq 202 ]]; then
				keep_going=1
				break
			fi
		done
		[[ $keep_going -eq 0 ]] && break

		sleep 1
		for i in $(seq $start $end); do
			if [[ ${rc[$i]} -eq 202 ]]; then
				rc[$i]=$(add_leaf $s $cli $i)
				if [[ ${rc[$i]} -eq 200 ]]; then
					if ! keys $s; then
						fail "$desc (data \"$i\"): ascii keys in response $(debug_response $s)"
					fi
				fi
			fi
		done
	done

	local all_good=1
	for i in $(seq $start $end); do
		if [[ ${rc[$i]} -ne 200 ]]; then
			fail "$desc (data \"$i\") HTTP status code: ${rc[$i]}"
			all_good=0
		fi
		echo ${rc[$i]} > "$log_dir/subs/$s/$i"
	done
	[[ $all_good -eq 1 ]] && pass $desc
}

function add_leaf() {
	local s=$1; shift
	local cli=$1; shift
	local data="$1"; shift
	local log_dir=${nvars[$s:log_dir]}

	echo "message=$(openssl dgst -binary <(echo $data) | b16encode)" > $log_dir/req
	echo "signature=$(echo $data |
		./sigsum-debug leaf sign -k $(cat ${nvars[$cli:log_dir]}/cli.key))" >> $log_dir/req
	echo "public_key=$(cat ${nvars[$cli:log_dir]}/cli.key.pub)" >> $log_dir/req

	cat $log_dir/req |
		curl -s -w "%{http_code}" -H "sigsum-token: test.sigsum.org ${nvars[$s:token]}" \
		     --data-binary @- ${nvars[$s:log_url]}/add-leaf \
		     >$log_dir/rsp

	echo $(status_code $s)
}

function test_cosignature() {
	local pri=$1; shift
	local log_dir=${nvars[$pri:log_dir]}
	local desc="POST add-cosignature (witness $1)"
	local now=$(date +%s)

	echo "cosignature=$1 $now $(curl -s ${nvars[$pri:log_url]}/get-next-tree-head |
		./sigsum-debug head sign -k $(cat $2) -t $now -h ${nvars[$pri:ssrv_key_hash]})" > $log_dir/req
	cat $log_dir/req |
		curl -s -w "%{http_code}" --data-binary @- ${nvars[$pri:log_url]}/add-cosignature \
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
	cat ${nvars[$i:log_dir]}/rsp
}

function status_code() {
	local i=$1; shift
	tail -n1 ${nvars[$i:log_dir]}/rsp
}

function value_of() {
	local s=$1; shift
	value_of_file ${nvars[$s:log_dir]}/rsp $@
}

function value_of_file() {
	local rsp=$1; shift
	while read line; do
		key=$(echo $line | cut -d"=" -f1)
		if [[ $key != $1 ]]; then
			continue
		fi

		value=$(echo $line | cut -d"=" -f2)
		echo $value
	done < <(head --lines=-1 $rsp)
}

function keys() {
        local s=$1; shift
	declare -A map
	map[thedummystring]=to_avoid_error_on_size_zero
	while read line; do
		key=$(echo $line | cut -d"=" -f1)
		map[$key]=ok
	done < <(head --lines=-1 ${nvars[$s:log_dir]}/rsp)

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

# Is proces with PID $1 running or not?
function pp() {
	[[ $1 == -p ]] && shift
	[[ -d /proc/$1 ]]
}

function b16encode {
	python3 -c 'import sys; sys.stdout.write(sys.stdin.buffer.read().hex())'
}

function b16decode {
	python3 -c 'import sys; sys.stdout.buffer.write(bytes.fromhex(sys.stdin.read()))'
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

main $@

# Local Variables:
# sh-basic-offset: 8
# End:
