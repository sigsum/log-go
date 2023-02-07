package witness

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"

	"sigsum.org/sigsum-go/pkg/ascii"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/types"
)

const (
	userAgent = "log-go server"
)

var (
	endpointAddTreeHead = types.Endpoint("add-tree-head")
	endpointGetTreeSize = types.Endpoint("get-tree-size/")
	errBadOldsize       = errors.New("bad old size")
)

type WitnessConfig struct {
	Url    string // Base url
	PubKey crypto.PublicKey
}

// Not concurrency safe (assuming http.Client isn't safe).
type client struct {
	cli            http.Client
	pubKey         crypto.PublicKey
	logKeyHash     crypto.Hash
	addTreeHeadUrl string
	getTreeSizeUrl string
}

func NewClient(config *WitnessConfig, logKeyHash *crypto.Hash) *client {
	return &client{
		pubKey:         config.PubKey,
		logKeyHash:     *logKeyHash,
		addTreeHeadUrl: endpointAddTreeHead.Path(config.Url),
		getTreeSizeUrl: endpointGetTreeSize.Path(config.Url),
	}
}

func reqToASCII(logKeyHash *crypto.Hash, sth *types.SignedTreeHead,
	oldSize uint64, proof *types.ConsistencyProof) (io.Reader, error) {
	buf := bytes.Buffer{}
	if err := ascii.WriteHash(&buf, "key_hash", logKeyHash); err != nil {
		return nil, err
	}
	if err := sth.ToASCII(&buf); err != nil {
		return nil, err
	}
	if err := ascii.WriteInt(&buf, "old_size", oldSize); err != nil {
		return nil, err
	}
	if err := proof.ToASCII(&buf); err != nil {
		return nil, err
	}
	return &buf, nil
}

func (c *client) AddTreeHead(ctx context.Context,
	sth *types.SignedTreeHead, oldSize uint64,
	proof *types.ConsistencyProof) (types.Cosignature, error) {
	body, err := reqToASCII(&c.logKeyHash, sth, oldSize, proof)
	if err != nil {
		return types.Cosignature{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.addTreeHeadUrl, body)
	if err != nil {
		return types.Cosignature{}, err
	}
	req.Header.Set("User-Agent", userAgent)
	rsp, err := c.cli.Do(req)
	if err != nil {
		return types.Cosignature{}, err
	}
	defer rsp.Body.Close()
	switch rsp.StatusCode {
	case http.StatusUnprocessableEntity:
		return types.Cosignature{}, errBadOldsize
	case http.StatusOK:
		var cs types.Cosignature
		err := cs.FromASCII(rsp.Body)
		if err != nil {
			return types.Cosignature{}, errBadOldsize
		}
		if !cs.Verify(&c.pubKey, &c.logKeyHash, &sth.TreeHead) {
			return types.Cosignature{}, fmt.Errorf("invalid cosignature")
		}
		return cs, nil
	default:
		b, err := io.ReadAll(rsp.Body)
		if err != nil {
			return types.Cosignature{},
				fmt.Errorf("request failed, status: %v", rsp.Status)
		}
		return types.Cosignature{}, fmt.Errorf("request failed, status %v, server: %q", rsp.Status, b)
	}
}

func (c *client) GetTreeSize(ctx context.Context) (uint64, error) {
	req, err := http.NewRequestWithContext(
		ctx, http.MethodGet,
		fmt.Sprintf("%s/%x", c.getTreeSizeUrl, c.logKeyHash),
		nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", userAgent)
	rsp, err := c.cli.Do(req)
	if err != nil {
		return 0, err
	}
	defer rsp.Body.Close()
	switch rsp.StatusCode {
	case http.StatusOK:
		p := ascii.NewParser(rsp.Body)
		size, err := p.GetInt("size")
		if err != nil {
			return 0, err
		}
		return size, p.GetEOF()
	default:
		b, err := io.ReadAll(rsp.Body)
		if err != nil {
			return 0, fmt.Errorf("request failed, status: %v", rsp.Status)
		}
		return 0, fmt.Errorf("request failed, status %v, server: %q", rsp.Status, b)
	}
}
