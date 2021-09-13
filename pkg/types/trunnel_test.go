package types

import (
	"bytes"
	"reflect"
	"testing"
)

var (
	testBuffer32 = &[32]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31}
	testBuffer64 = &[64]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63}
)

func TestMarshalMessage(t *testing.T) {
	description := "valid: shard hint 72623859790382856, checksum 0x00,0x01,..."
	message := &Message{
		ShardHint: 72623859790382856,
		Checksum:  testBuffer32,
	}
	want := bytes.Join([][]byte{
		[]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		testBuffer32[:],
	}, nil)
	if got := message.Marshal(); !bytes.Equal(got, want) {
		t.Errorf("got message\n\t%v\nbut wanted\n\t%v\nin test %q\n", got, want, description)
	}
}

func TestMarshalLeaf(t *testing.T) {
	description := "valid: shard hint 72623859790382856, buffers 0x00,0x01,..."
	leaf := &Leaf{
		Message: Message{
			ShardHint: 72623859790382856,
			Checksum:  testBuffer32,
		},
		SigIdent: SigIdent{
			Signature: testBuffer64,
			KeyHash:   testBuffer32,
		},
	}
	want := bytes.Join([][]byte{
		[]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		testBuffer32[:], testBuffer64[:], testBuffer32[:],
	}, nil)
	if got := leaf.Marshal(); !bytes.Equal(got, want) {
		t.Errorf("got leaf\n\t%v\nbut wanted\n\t%v\nin test %q\n", got, want, description)
	}
}

func TestMarshalTreeHead(t *testing.T) {
	description := "valid: timestamp 16909060, tree size 72623859790382856, root hash & key hash 0x00,0x01,..."
	th := &TreeHead{
		Timestamp: 16909060,
		TreeSize:  72623859790382856,
		RootHash:  testBuffer32,
		KeyHash:   testBuffer32,
	}
	want := bytes.Join([][]byte{
		[]byte{0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04},
		[]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		testBuffer32[:],
		testBuffer32[:],
	}, nil)
	if got := th.Marshal(); !bytes.Equal(got, want) {
		t.Errorf("got tree head\n\t%v\nbut wanted\n\t%v\nin test %q\n", got, want, description)
	}
}

func TestUnmarshalLeaf(t *testing.T) {
	for _, table := range []struct {
		description string
		serialized  []byte
		wantErr     bool
		want        *Leaf
	}{
		{
			description: "invalid: not enough bytes",
			serialized:  make([]byte, LeafSize-1),
			wantErr:     true,
		},
		{
			description: "invalid: too many bytes",
			serialized:  make([]byte, LeafSize+1),
			wantErr:     true,
		},
		{
			description: "valid: shard hint 72623859790382856, buffers 0x00,0x01,...",
			serialized: bytes.Join([][]byte{
				[]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
				testBuffer32[:], testBuffer64[:], testBuffer32[:],
			}, nil),
			want: &Leaf{
				Message: Message{
					ShardHint: 72623859790382856,
					Checksum:  testBuffer32,
				},
				SigIdent: SigIdent{
					Signature: testBuffer64,
					KeyHash:   testBuffer32,
				},
			},
		},
	} {
		var leaf Leaf
		err := leaf.Unmarshal(table.serialized)
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.description, err)
		}
		if err != nil {
			continue
		}
		if got, want := &leaf, table.want; !reflect.DeepEqual(got, want) {
			t.Errorf("got leaf\n\t%v\nbut wanted\n\t%v\nin test %q\n", got, want, table.description)
		}
	}
}
