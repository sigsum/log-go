package types

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"strconv"
)

const (
	// Delim is a key-value separator
	Delim = "="

	// EOL is a line sepator
	EOL = "\n"

	// NumField* is the number of unique keys in an incoming ASCII message
	NumFieldLeaf                    = 4
	NumFieldSignedTreeHead          = 4
	NumFieldConsistencyProof        = 3
	NumFieldInclusionProof          = 3
	NumFieldLeavesRequest           = 2
	NumFieldInclusionProofRequest   = 2
	NumFieldConsistencyProofRequest = 2
	NumFieldLeafRequest             = 5
	NumFieldCosignatureRequest      = 2

	// New leaf keys
	ShardHint       = "shard_hint"
	Checksum        = "checksum"
	Signature       = "signature"
	VerificationKey = "verification_key"
	DomainHint      = "domain_hint"

	// Inclusion proof keys
	LeafHash      = "leaf_hash"
	LeafIndex     = "leaf_index"
	InclusionPath = "inclusion_path"

	// Consistency proof keys
	NewSize         = "new_size"
	OldSize         = "old_size"
	ConsistencyPath = "consistency_path"

	// Range of leaves keys
	StartSize = "start_size"
	EndSize   = "end_size"

	// Tree head keys
	Timestamp = "timestamp"
	TreeSize  = "tree_size"
	RootHash  = "root_hash"

	// Witness signature-identity keys
	KeyHash     = "key_hash"
	Cosignature = "cosignature"
)

// MessageASCI is a wrapper that manages ASCII key-value pairs
type MessageASCII struct {
	m map[string][]string
}

// NewMessageASCII unpacks an incoming ASCII message
func NewMessageASCII(r io.Reader, numFieldExpected int) (*MessageASCII, error) {
	buf, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("ReadAll: %v", err)
	}
	lines := bytes.Split(buf, []byte(EOL))
	if len(lines) <= 1 {
		return nil, fmt.Errorf("Not enough lines: empty")
	}
	lines = lines[:len(lines)-1] // valid message => split gives empty last line

	msg := MessageASCII{make(map[string][]string)}
	for _, line := range lines {
		split := bytes.Index(line, []byte(Delim))
		if split == -1 {
			return nil, fmt.Errorf("invalid line: %v", string(line))
		}

		key := string(line[:split])
		value := string(line[split+len(Delim):])
		values, ok := msg.m[key]
		if !ok {
			values = nil
			msg.m[key] = values
		}
		msg.m[key] = append(values, value)
	}

	if msg.NumField() != numFieldExpected {
		return nil, fmt.Errorf("Unexpected number of keys: %v", msg.NumField())
	}
	return &msg, nil
}

// NumField returns the number of unique keys
func (msg *MessageASCII) NumField() int {
	return len(msg.m)
}

// GetStrings returns a list of strings
func (msg *MessageASCII) GetStrings(key string) []string {
	strs, ok := msg.m[key]
	if !ok {
		return nil
	}
	return strs
}

// GetString unpacks a string
func (msg *MessageASCII) GetString(key string) (string, error) {
	strs := msg.GetStrings(key)
	if len(strs) != 1 {
		return "", fmt.Errorf("expected one string: %v", strs)
	}
	return strs[0], nil
}

// GetUint64 unpacks an uint64
func (msg *MessageASCII) GetUint64(key string) (uint64, error) {
	str, err := msg.GetString(key)
	if err != nil {
		return 0, fmt.Errorf("GetString: %v", err)
	}
	num, err := strconv.ParseUint(str, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("ParseUint: %v", err)
	}
	return num, nil
}

// GetHash unpacks a hash
func (msg *MessageASCII) GetHash(key string) (*[HashSize]byte, error) {
	str, err := msg.GetString(key)
	if err != nil {
		return nil, fmt.Errorf("GetString: %v", err)
	}

	var hash [HashSize]byte
	if err := decodeHex(str, hash[:]); err != nil {
		return nil, fmt.Errorf("decodeHex: %v", err)
	}
	return &hash, nil
}

// GetSignature unpacks a signature
func (msg *MessageASCII) GetSignature(key string) (*[SignatureSize]byte, error) {
	str, err := msg.GetString(key)
	if err != nil {
		return nil, fmt.Errorf("GetString: %v", err)
	}

	var signature [SignatureSize]byte
	if err := decodeHex(str, signature[:]); err != nil {
		return nil, fmt.Errorf("decodeHex: %v", err)
	}
	return &signature, nil
}

// GetVerificationKey unpacks a verification key
func (msg *MessageASCII) GetVerificationKey(key string) (*[VerificationKeySize]byte, error) {
	str, err := msg.GetString(key)
	if err != nil {
		return nil, fmt.Errorf("GetString: %v", err)
	}

	var vk [VerificationKeySize]byte
	if err := decodeHex(str, vk[:]); err != nil {
		return nil, fmt.Errorf("decodeHex: %v", err)
	}
	return &vk, nil
}

// decodeHex decodes a hex-encoded string into an already-sized byte slice
func decodeHex(str string, out []byte) error {
	buf, err := hex.DecodeString(str)
	if err != nil {
		return fmt.Errorf("DecodeString: %v", err)
	}
	if len(buf) != len(out) {
		return fmt.Errorf("invalid length: %v", len(buf))
	}
	copy(out, buf)
	return nil
}

/*
 *
 * MarshalASCII wrappers for types that the log server outputs
 *
 */
func (l *Leaf) MarshalASCII(w io.Writer) error {
	if err := writeASCII(w, ShardHint, strconv.FormatUint(l.ShardHint, 10)); err != nil {
		return fmt.Errorf("writeASCII: %v", err)
	}
	if err := writeASCII(w, Checksum, hex.EncodeToString(l.Checksum[:])); err != nil {
		return fmt.Errorf("writeASCII: %v", err)
	}
	if err := writeASCII(w, Signature, hex.EncodeToString(l.Signature[:])); err != nil {
		return fmt.Errorf("writeASCII: %v", err)
	}
	if err := writeASCII(w, KeyHash, hex.EncodeToString(l.KeyHash[:])); err != nil {
		return fmt.Errorf("writeASCII: %v", err)
	}
	return nil
}

func (sth *SignedTreeHead) MarshalASCII(w io.Writer) error {
	if err := writeASCII(w, Timestamp, strconv.FormatUint(sth.Timestamp, 10)); err != nil {
		return fmt.Errorf("writeASCII: %v", err)
	}
	if err := writeASCII(w, TreeSize, strconv.FormatUint(sth.TreeSize, 10)); err != nil {
		return fmt.Errorf("writeASCII: %v", err)
	}
	if err := writeASCII(w, RootHash, hex.EncodeToString(sth.RootHash[:])); err != nil {
		return fmt.Errorf("writeASCII: %v", err)
	}
	if err := writeASCII(w, Signature, hex.EncodeToString(sth.Signature[:])); err != nil {
		return fmt.Errorf("writeASCII: %v", err)
	}
	return nil
}

func (cth *CosignedTreeHead) MarshalASCII(w io.Writer) error {
	if err := cth.SignedTreeHead.MarshalASCII(w); err != nil {
		return fmt.Errorf("writeASCII: %v", err)
	}
	for _, si := range cth.SigIdent {
		if err := si.MarshalASCII(w); err != nil {
			return fmt.Errorf("writeASCII: %v", err)
		}
	}
	return nil
}

func (si *SigIdent) MarshalASCII(w io.Writer) error {
	if err := writeASCII(w, KeyHash, hex.EncodeToString(si.KeyHash[:])); err != nil {
		return fmt.Errorf("writeASCII: %v", err)
	}
	if err := writeASCII(w, Cosignature, hex.EncodeToString(si.Signature[:])); err != nil {
		return fmt.Errorf("writeASCII: %v", err)
	}
	return nil
}

func (p *ConsistencyProof) MarshalASCII(w io.Writer) error {
	for _, hash := range p.Path {
		if err := writeASCII(w, ConsistencyPath, hex.EncodeToString(hash[:])); err != nil {
			return fmt.Errorf("writeASCII: %v", err)
		}
	}
	return nil
}

func (p *InclusionProof) MarshalASCII(w io.Writer) error {
	if err := writeASCII(w, LeafIndex, strconv.FormatUint(p.LeafIndex, 10)); err != nil {
		return fmt.Errorf("writeASCII: %v", err)
	}
	for _, hash := range p.Path {
		if err := writeASCII(w, InclusionPath, hex.EncodeToString(hash[:])); err != nil {
			return fmt.Errorf("writeASCII: %v", err)
		}
	}
	return nil
}

func writeASCII(w io.Writer, key, value string) error {
	if _, err := fmt.Fprintf(w, "%s%s%s%s", key, Delim, value, EOL); err != nil {
		return fmt.Errorf("Fprintf: %v", err)
	}
	return nil
}

/*
 *
 * Unmarshal ASCII wrappers that the log server and/or log clients receive.
 *
 */
func (ll *LeafList) UnmarshalASCII(r io.Reader) error {
	return nil
}

func (sth *SignedTreeHead) UnmarshalASCII(r io.Reader) error {
	msg, err := NewMessageASCII(r, NumFieldSignedTreeHead)
	if err != nil {
		return fmt.Errorf("NewMessageASCII: %v", err)
	}

	if sth.Timestamp, err = msg.GetUint64(Timestamp); err != nil {
		return fmt.Errorf("GetUint64(Timestamp): %v", err)
	}
	if sth.TreeSize, err = msg.GetUint64(TreeSize); err != nil {
		return fmt.Errorf("GetUint64(TreeSize): %v", err)
	}
	if sth.RootHash, err = msg.GetHash(RootHash); err != nil {
		return fmt.Errorf("GetHash(RootHash): %v", err)
	}
	if sth.Signature, err = msg.GetSignature(Signature); err != nil {
		return fmt.Errorf("GetHash(RootHash): %v", err)
	}
	return nil
}

func (p *InclusionProof) UnmarshalASCII(r io.Reader) error {
	return nil
}

func (p *ConsistencyProof) UnmarshalASCII(r io.Reader) error {
	return nil
}

func (req *InclusionProofRequest) UnmarshalASCII(r io.Reader) error {
	msg, err := NewMessageASCII(r, NumFieldInclusionProofRequest)
	if err != nil {
		return fmt.Errorf("NewMessageASCII: %v", err)
	}

	if req.LeafHash, err = msg.GetHash(LeafHash); err != nil {
		return fmt.Errorf("GetHash(LeafHash): %v", err)
	}
	if req.TreeSize, err = msg.GetUint64(TreeSize); err != nil {
		return fmt.Errorf("GetUint64(TreeSize): %v", err)
	}
	return nil
}

func (req *ConsistencyProofRequest) UnmarshalASCII(r io.Reader) error {
	msg, err := NewMessageASCII(r, NumFieldConsistencyProofRequest)
	if err != nil {
		return fmt.Errorf("NewMessageASCII: %v", err)
	}

	if req.NewSize, err = msg.GetUint64(NewSize); err != nil {
		return fmt.Errorf("GetUint64(NewSize): %v", err)
	}
	if req.OldSize, err = msg.GetUint64(OldSize); err != nil {
		return fmt.Errorf("GetUint64(OldSize): %v", err)
	}
	return nil
}

func (req *LeavesRequest) UnmarshalASCII(r io.Reader) error {
	msg, err := NewMessageASCII(r, NumFieldLeavesRequest)
	if err != nil {
		return fmt.Errorf("NewMessageASCII: %v", err)
	}

	if req.StartSize, err = msg.GetUint64(StartSize); err != nil {
		return fmt.Errorf("GetUint64(StartSize): %v", err)
	}
	if req.EndSize, err = msg.GetUint64(EndSize); err != nil {
		return fmt.Errorf("GetUint64(EndSize): %v", err)
	}
	return nil
}

func (req *LeafRequest) UnmarshalASCII(r io.Reader) error {
	msg, err := NewMessageASCII(r, NumFieldLeafRequest)
	if err != nil {
		return fmt.Errorf("NewMessageASCII: %v", err)
	}

	if req.ShardHint, err = msg.GetUint64(ShardHint); err != nil {
		return fmt.Errorf("GetUint64(ShardHint): %v", err)
	}
	if req.Checksum, err = msg.GetHash(Checksum); err != nil {
		return fmt.Errorf("GetHash(Checksum): %v", err)
	}
	if req.Signature, err = msg.GetSignature(Signature); err != nil {
		return fmt.Errorf("GetSignature: %v", err)
	}
	if req.VerificationKey, err = msg.GetVerificationKey(VerificationKey); err != nil {
		return fmt.Errorf("GetVerificationKey: %v", err)
	}
	if req.DomainHint, err = msg.GetString(DomainHint); err != nil {
		return fmt.Errorf("GetString(DomainHint): %v", err)
	}
	return nil
}

func (req *CosignatureRequest) UnmarshalASCII(r io.Reader) error {
	msg, err := NewMessageASCII(r, NumFieldCosignatureRequest)
	if err != nil {
		return fmt.Errorf("NewMessageASCII: %v", err)
	}

	if req.Signature, err = msg.GetSignature(Cosignature); err != nil {
		return fmt.Errorf("GetSignature: %v", err)
	}
	if req.KeyHash, err = msg.GetHash(KeyHash); err != nil {
		return fmt.Errorf("GetHash(KeyHash): %v", err)
	}
	return nil
}
