# Run Trillian + sigsum-log-go locally
Trillian uses a database.  So, we will need to set that up.  It is documented
[here](https://github.com/google/trillian#mysql-setup), and how to check that it
is setup properly
[here](https://github.com/google/certificate-transparency-go/blob/master/trillian/docs/ManualDeployment.md#data-storage).

Other than the database we need Trillian log signer, Trillian log server, and
sigsum-log-go. sigsum-log-go has been tested with trillian v.1.3.13.
```
$ go install github.com/google/trillian/cmd/trillian_log_signer@v1.3.13
$ go install github.com/google/trillian/cmd/trillian_log_server@v1.3.13
$ go install
```

Start Trillian log signer:
```
trillian_log_signer --logtostderr -v 9 --force_master --rpc_endpoint=localhost:6961 --http_endpoint=localhost:6964 --num_sequencers 1 --sequencer_interval 100ms --batch_size 100
```

Start Trillian log server:
```
trillian_log_server --logtostderr -v 9 --rpc_endpoint=localhost:6962 --http_endpoint=localhost:6963
```

As described in more detail
[here](https://github.com/google/certificate-transparency-go/blob/master/trillian/docs/ManualDeployment.md#trillian-services),
we need to provision a Merkle tree once:
```
$ go install github.com/google/trillian/cmd/createtree@v1.3.13
$ createtree --admin_server localhost:6962
<tree id>
```

Hang on to `<tree id>`.  Our sigsum-log-go instance will use it when talking to
the Trillian log server to specify which Merkle tree we are working against.

(If you take a look in the `Trees` table you will see that the tree has been
provisioned.)

We will also need a public key-pair for sigsum-log-go.
```
$ go install golang.sigsum.org/sigsum-log-go/cmd/tmp/keygen@v1.3.13
$ ./keygen
sk: <sk>
vk: <vk>
```

Start sigsum-log-go:
```
$ tree_id=<tree_id>
$ sk=<sk>
$ sigsum_log_go --logtostderr -v 9 --http_endpoint localhost:6965 --log_rpc_server localhost:6962 --trillian_id $tree_id --key $sk
```

Quick test:
- curl http://localhost:6965/sigsum/v0/get-tree-head-latest
- try `submit` and `cosign` commands in `cmd/tmp`
