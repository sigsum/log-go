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
declare -r mysql_uri='sigsum_test:zaphod@tcp(127.0.0.1:3306)/sigsum_test'

function main() {
	local testflavour=basic
	[[ $# > 0 ]] && { testflavour=$1; shift; }

	check_go_deps

	node_setup $loga $logb

	# Primary
	nvars[$loga:ssrv_extra_args]="-secondary-url=http://${nvars[$logb:int_url]}"
	nvars[$loga:ssrv_extra_args]+=" -secondary-pubkey=${nvars[$logb:ssrv_pub]}"
	node_start $loga

	# Secondary
	nvars[$logb:ssrv_extra_args]="-primary-url=http://${nvars[$loga:int_url]}"
	nvars[$logb:ssrv_extra_args]+=" -primary-pubkey=${nvars[$loga:ssrv_pub]}"
	node_start $logb

	client_setup $client
	check_setup $loga $logb
	run_tests $loga $logb 0 5
	run_tests $loga $logb 5 1

	if [[ $testflavour == extended ]]; then
		# for tree equality tests later on; FIXME: remove
		test_signed_tree_head $loga 6
		cp ${nvars[$loga:log_dir]}/rsp ${nvars[$loga:log_dir]}/last_sth

		node_stop_fe $loga $logb
		node_destroy $loga; node_stop_be $loga
		node_setup $logc

		node_promote $logb $loga
		nvars[$logb:ssrv_extra_args]="-secondary-url=http://${nvars[$logc:int_url]}"
		nvars[$logb:ssrv_extra_args]+=" -secondary-pubkey=${nvars[$logc:ssrv_pub]}"
		node_start_fe $logb

		nvars[$logc:ssrv_extra_args]="-primary-url=http://${nvars[$logb:int_url]}"
		nvars[$logc:ssrv_extra_args]+=" -primary-pubkey=${nvars[$logb:ssrv_pub]}"
		nodes+=" logc"
		node_start $logc

		check_setup $logb $logc
		run_tests_extended $logb $logc 6 ${nvars[$loga:log_dir]}/last_sth
	fi
}

function check_go_deps() {
	[[ $(command -v trillian_log_signer)  ]] || die "Hint: go install github.com/google/trillian/cmd/trillian_log_signer"
	[[ $(command -v trillian_log_server)  ]] || die "Hint: go install github.com/google/trillian/cmd/trillian_log_server"
	[[ $(command -v createtree)           ]] || die "Hint: go install github.com/google/trillian/cmd/createtree"
	[[ $(command -v deletetree)           ]] || die "Hint: go install github.com/google/trillian/cmd/deletetree"
	[[ $(command -v updatetree)           ]] || die "Hint: go install github.com/google/trillian/cmd/updatetree"
	go build -o sigsum-debug sigsum.org/sigsum-go/cmd/sigsum-debug
}

function client_setup() {
	# NOTE: not ready for multiple clients --  stomping on everything
	for i in $@; do
		info "setting up client ($i)"
		if [[ -f $1 ]];
		then
			source $1
		else
			cli_priv=$(./sigsum-debug key private)
			cli_domain_hint=_sigsum_v0.example.com
		fi
		cli_pub=$(echo $cli_priv | ./sigsum-debug key public)
		cli_key_hash=$(echo $cli_pub | ./sigsum-debug key hash)

		[[ $cli_domain_hint =~ ^_sigsum_v0..+ ]] ||
			die "must have a valid domain hint"

		if [[ $g_offline_mode -ne 1 ]]; then
			verify_domain_hint_in_dns $cli_domain_hint $cli_key_hash
		fi
	done
}

function verify_domain_hint_in_dns() {
	local domain_hint=$1; shift
	local key_hash=$1; shift

	for line in $(dig +short -t txt $domain_hint); do
		key_hash=${line:1:${#line}-2}
		if [[ $key_hash == $key_hash ]]; then
			return
		fi
	done

	die "must have a properly configured domain hint"
}

function node_setup() {
	for i in $@; do
		local dir=$(mktemp -d /tmp/sigsum-log-test.XXXXXXXXXX)
		info "$i: logging to $dir"
		nvars[$i:log_dir]=$dir
		trillian_setup $i
		sigsum_setup $i
	done
}

# node_start starts trillian and sigsum and creates new trees
function node_start() {
	for i in $@; do
		trillian_start $i
		sigsum_start $i
	done
}

# node_start_* starts sequencer and sigsum but does not create new trees
function node_start_fe() {
	trillian_start_sequencer $@
	sigsum_start $@
}

function node_start_be() {
	trillian_start_server $@
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
	nvars[$new_primary:ssrv_priv]=${nvars[$prev_primary:ssrv_priv]}
	nvars[$new_primary:ssrv_pub]=${nvars[$prev_primary:ssrv_pub]}
	nvars[$new_primary:ssrv_key_hash]=${nvars[$prev_primary:ssrv_key_hash]}
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

		nvars[$i:wit1_priv]=$(./sigsum-debug key private)
		nvars[$i:wit1_pub]=$(echo ${nvars[$i:wit1_priv]} | ./sigsum-debug key public)
		nvars[$i:wit1_key_hash]=$(echo ${nvars[$i:wit1_pub]} | ./sigsum-debug key hash)
		nvars[$i:wit2_priv]=$(./sigsum-debug key private)
		nvars[$i:wit2_pub]=$(echo ${nvars[$i:wit2_priv]} | ./sigsum-debug key public)
		nvars[$i:wit2_key_hash]=$(echo ${nvars[$i:wit2_pub]} | ./sigsum-debug key hash)
		nvars[$i:ssrv_witnesses]=${nvars[$i:wit1_pub]},${nvars[$i:wit2_pub]}

		nvars[$i:ssrv_priv]=$(./sigsum-debug key private)
		nvars[$i:ssrv_pub]=$(echo ${nvars[$i:ssrv_priv]} | ./sigsum-debug key public)
		nvars[$i:ssrv_key_hash]=$(echo ${nvars[$i:ssrv_pub]} | ./sigsum-debug key hash)
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
		info "starting Sigsum log $role node ($i)"

		args="$extra_args \
                      -url-prefix=${nvars[$i:ssrv_prefix]} \
		      -tree-id=${nvars[$i:ssrv_tree_id]} \
		      -trillian-rpc-server=${nvars[$i:tsrv_rpc]} \
		      -interval=${nvars[$i:ssrv_interval]}s \
		      -external-endpoint=${nvars[$i:ssrv_endpoint]} \
		      -internal-endpoint=${nvars[$i:ssrv_internal]} \
		      -log-level=debug \
		      -log-file=${nvars[$i:log_dir]}/sigsum-log.log"
		# Can't use go run, because then we don't get the right pid to kill for cleanup.
		go build -o $binary ../cmd/$binary/main.go
		./$binary $args -key=<(echo ${nvars[$i:ssrv_priv]}) \
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
	for i in $@; do
		if ! deletetree -admin_server=$tsrv_rpc -log_id=${nvars[$i:ssrv_tree_id]} -logtostderr 2>/dev/null; then
			warn "failed deleting provisioned Merkle tree ${nvars[$i:ssrv_tree_id]}"
		else
			info "deleted provisioned Merkle tree ${nvars[$i:ssrv_tree_id]}"
		fi
	done
}

function node_stop_fe() {
	for i in $@; do

		[[ -v nvars[$i:ssrv_pid] ]] && pp ${nvars[$i:ssrv_pid]} && kill ${nvars[$i:ssrv_pid]} # FIXME: why is SIGINT (often) not enough?
		[[ -v nvars[$i:tseq_pid] ]] && pp ${nvars[$i:tseq_pid]} && kill -2 ${nvars[$i:tseq_pid]}
		while :; do
			sleep 1

			[[ -v nvars[$i:tseq_pid] ]] && pp ${nvars[$i:tseq_pid]} && continue
			[[ -v nvars[$i:ssrv_pid] ]] && pp ${nvars[$i:ssrv_pid]} && continue

			break
		done
		info "stopped Trillian log sequencer ($i)"
		info "stopped Sigsum log server ($i)"

	done
}

function node_stop_be() {
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
		if [[ ${nvars[$i:ssrv_role]} == primary ]]; then
			[[ -v nvars[$i:tseq_pid] ]] && pp ${nvars[$i:tseq_pid]} || die "must have Trillian log sequencer ($i)"
		fi
		[[ -v nvars[$i:tsrv_pid] ]] && pp ${nvars[$i:tsrv_pid]} || die "must have Trillian log server ($i)"
		[[ -v nvars[$i:ssrv_pid] ]] && pp ${nvars[$i:ssrv_pid]} || die "must have Sigsum log server ($i)"
	done
}

function run_tests() {
	local pri=$1; shift
	local sec=$1; shift
	local start_leaf=$1; shift # 0-based
	local num_leaf=$1; shift

	info "running ordinary tests, pri=$pri, start_leaf=$start_leaf, num_leaf=$num_leaf"

	test_signed_tree_head $pri $start_leaf

	info "adding $num_leaf leaves"
	test_add_leaves $pri $(( $start_leaf + 1 )) $num_leaf
	num_leaf=$(( $num_leaf + $start_leaf ))

	test_signed_tree_head $pri $num_leaf
	for i in $(seq $(( $start_leaf + 1 )) $(( $num_leaf - 1 ))); do
		test_consistency_proof $pri $i $num_leaf
	done

	test_cosignature $pri ${nvars[$pri:wit1_key_hash]} ${nvars[$pri:wit1_priv]}
	test_cosignature $pri ${nvars[$pri:wit2_key_hash]} ${nvars[$pri:wit2_priv]}

	info "waiting for cosignature(s) to be available..."
	sleep ${nvars[$pri:ssrv_interval]}

	test_cosigned_tree_head $pri $num_leaf
	for i in $(seq  $(( $start_leaf + 1 )) $num_leaf); do
		test_inclusion_proof $pri $num_leaf $i $(( $i - 1 ))
	done

	for i in $(seq  $(( $start_leaf + 1 )) $num_leaf); do
		test_get_leaf $pri $i $(( $i - 1 ))
	done

	warn "no signatures and merkle proofs were verified"
}

run_tests_extended() {
	local pri=$1; shift
	local sec=$1; shift
	local current_tree_size=$1; shift
	local old_pri_sth_rsp=$1; shift
	info "running extended tests"

	info "wait for new primary and secondary to catch up and merge"
	sleep $(( ${nvars[$pri:ssrv_interval]} + ${nvars[$sec:ssrv_interval]} + 1 ))

	test_signed_tree_head $pri $current_tree_size
	test_tree_heads_equal ${nvars[$pri:log_dir]}/rsp $old_pri_sth_rsp

	run_tests $pri $sec $current_tree_size 5
}

function test_signed_tree_head() {
	local pri=$1; shift
	local tree_size=$1; shift
	local log_dir=${nvars[$pri:log_dir]}
	local desc="GET get-tree-head-to-cosign (tree size $tree_size)"

	curl -s -w "%{http_code}" ${nvars[$pri:log_url]}/get-tree-head-to-cosign \
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
		fail "$desc: timestamp $(value_of $pri "timestamp") is too high"
		return
	fi
	if [[ $(value_of $pri "timestamp") -lt $(( $now - ${nvars[$pri:ssrv_interval]} - 1 )) ]]; then
		fail "$desc: timestamp $(value_of $pri "timestamp") is too low"
		return
	fi

	if [[ $(value_of $pri "tree_size") != $tree_size ]]; then
		fail "$desc: tree size $(value_of $pri "tree_size")"
		return
	fi

	# TODO: verify tree head signature
	pass $desc
}

function test_tree_heads_equal() {
	local rsp1=$1; shift
	local rsp2=$1; shift
	local desc="comparing tree heads ($rsp1, $rsp2)"

	n1_tree_size=$(value_of_file $rsp1 "tree_size")
	n2_tree_size=$(value_of_file $rsp2 "tree_size")
	if [[ $n1_tree_size -ne $n2_tree_size ]]; then
		fail "$desc: tree_size: $n1_tree_size != $n2_tree_size"
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
	local tree_size=$1; shift
	local log_dir=${nvars[$pri:log_dir]}
	local desc="GET get-tree-head-cosigned (all witnesses), tree_size $tree_size"

	curl -s -w "%{http_code}" ${nvars[$pri:log_url]}/get-tree-head-cosigned \
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
	if [[ $(value_of $pri "timestamp") -lt $(( $now - ${nvars[$pri:ssrv_interval]} * 2 )) ]]; then
		fail "$desc: timestamp $(value_of $pri "timestamp") is too small"
		return
	fi

	if [[ $(value_of $pri "tree_size") != $tree_size ]]; then
		fail "$desc: tree size $(value_of $pri "tree_size")"
		return
	fi

	for got in $(value_of $pri key_hash); do
		found=""
		for want in ${nvars[$pri:wit1_key_hash]} ${nvars[$pri:wit2_key_hash]}; do
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
	local pri=$1; shift
	local tree_size=$1; shift
	local data=$1; shift
	local index=$1; shift
	local log_dir=${nvars[$pri:log_dir]}
	local desc="GET get-inclusion-proof (tree_size $tree_size, data \"$data\", index $index)"

	local signature=$(echo ${data} | ./sigsum-debug leaf sign -k $cli_priv)
	local leaf_hash=$(echo ${data} | ./sigsum-debug leaf hash -k $cli_key_hash -s $signature)
	curl -s -w "%{http_code}" ${nvars[$pri:log_url]}/get-inclusion-proof/${tree_size}/${leaf_hash} >${log_dir}/rsp

	if [[ $(status_code $pri) != 200 ]]; then
		fail "$desc: http status code $(status_code $pri)"
		return
	fi

	if ! keys $pri "leaf_index" "inclusion_path"; then
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

	if ! keys $pri "consistency_path"; then
		fail "$desc: ascii keys in response $(debug_response $pri)"
		return
	fi

	# TODO: verify consistency proof
	pass $desc
}

function test_get_leaf() {
	local pri=$1; shift
	local data="$1"; shift
	local index="$1"; shift
	local log_dir=${nvars[$pri:log_dir]}
	local desc="GET get-leaves (data \"$data\", index $index)"

	curl -s -w "%{http_code}" ${nvars[$pri:log_url]}/get-leaves/$index/$index >$log_dir/rsp

	if [[ $(status_code $pri) != 200 ]]; then
		fail "$desc: http status code $(status_code $pri)"
		return
	fi

	if ! keys $pri "checksum" "signature" "key_hash"; then
		fail "$desc: ascii keys in response $(debug_response $pri)"
		return
	fi

	local message=$(openssl dgst -binary <(echo $data) | b16encode)
	local checksum=$(openssl dgst -binary <(echo $message | b16decode) | b16encode)
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

function test_add_leaves() {
	local s=$1; shift
	local start=$1; shift	# integer, used as data and filename under subs/
	local end=$(( $start + $1 - 1 )); shift # number of leaves to add
	local desc="add leaves"
	local log_dir=${nvars[$s:log_dir]}
	[[ -d $log_dir/subs/$s ]] || mkdir -p $log_dir/subs/$s

	local -a rc
	for i in $(seq $start $end); do
		rc[$i]=$(add_leaf $s $i)
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
				rc[$i]=$(add_leaf $s $i)
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
	local data="$1"; shift
	local log_dir=${nvars[$s:log_dir]}

	echo "message=$(openssl dgst -binary <(echo $data) | b16encode)" > $log_dir/req
	echo "signature=$(echo $data |
		./sigsum-debug leaf sign -k $cli_priv)" >> $log_dir/req
	echo "public_key=$cli_pub" >> $log_dir/req

	cat $log_dir/req |
		curl -s -w "%{http_code}" --data-binary @- ${nvars[$s:log_url]}/add-leaf \
		     >$log_dir/rsp

	echo $(status_code $s)
}

function test_cosignature() {
	local pri=$1; shift
	local log_dir=${nvars[$pri:log_dir]}
	local desc="POST add-cosignature (witness $1)"

	echo "key_hash=$1" > $log_dir/req
	echo "cosignature=$(curl -s ${nvars[$pri:log_url]}/get-tree-head-to-cosign |
		./sigsum-debug head sign -k $2 -h ${nvars[$pri:ssrv_key_hash]})" >> $log_dir/req
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
