package types

import (
	"encoding/binary"
	"fmt"
)

const (
	// MessageSize is the number of bytes in a Trunnel-encoded leaf message
	MessageSize = 8 + HashSize
	// LeafSize is the number of bytes in a Trunnel-encoded leaf
	LeafSize = MessageSize + SignatureSize + HashSize
	// TreeHeadSize is the number of bytes in a Trunnel-encoded tree head
	TreeHeadSize = 8 + 8 + HashSize + HashSize
)

// Marshal returns a Trunnel-encoded message
func (m *Message) Marshal() []byte {
	buf := make([]byte, MessageSize)
	binary.BigEndian.PutUint64(buf, m.ShardHint)
	copy(buf[8:], m.Checksum[:])
	return buf
}

// Marshal returns a Trunnel-encoded leaf
func (l *Leaf) Marshal() []byte {
	buf := l.Message.Marshal()
	buf = append(buf, l.SigIdent.Signature[:]...)
	buf = append(buf, l.SigIdent.KeyHash[:]...)
	return buf
}

// Marshal returns a Trunnel-encoded tree head
func (th *TreeHead) Marshal() []byte {
	buf := make([]byte, TreeHeadSize)
	binary.BigEndian.PutUint64(buf[0:8], th.Timestamp)
	binary.BigEndian.PutUint64(buf[8:16], th.TreeSize)
	copy(buf[16:16+HashSize], th.RootHash[:])
	copy(buf[16+HashSize:], th.KeyHash[:])
	return buf
}

// Unmarshal parses the Trunnel-encoded buffer as a leaf
func (l *Leaf) Unmarshal(buf []byte) error {
	if len(buf) != LeafSize {
		return fmt.Errorf("invalid leaf size: %v", len(buf))
	}
	// Shard hint
	l.ShardHint = binary.BigEndian.Uint64(buf)
	offset := 8
	// Checksum
	l.Checksum = &[HashSize]byte{}
	copy(l.Checksum[:], buf[offset:offset+HashSize])
	offset += HashSize
	// Signature
	l.Signature = &[SignatureSize]byte{}
	copy(l.Signature[:], buf[offset:offset+SignatureSize])
	offset += SignatureSize
	// KeyHash
	l.KeyHash = &[HashSize]byte{}
	copy(l.KeyHash[:], buf[offset:])
	return nil
}
