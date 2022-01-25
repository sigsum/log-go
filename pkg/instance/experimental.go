package instance

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net/http"

	"git.sigsum.org/sigsum-lib-go/pkg/types"
	"github.com/golang/glog"
)

// algEd25519 identifies a checkpoint signature algorithm
const algEd25519 byte = 1

// getCheckpoint is an experimental endpoint that is not part of the official
// Sigsum API.  Documentation can be found in the transparency-dev repo.
func getCheckpoint(ctx context.Context, i *Instance, w http.ResponseWriter, r *http.Request) (int, error) {
	glog.V(3).Info("handling get-checkpoint request")
	sth, err := i.Stateman.ToCosignTreeHead(ctx)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	if err := i.signWriteNote(w, sth); err != nil {
		return http.StatusInternalServerError, err
	}
	return http.StatusOK, nil
}

// signWriteNote signs and writes a checkpoint which uses "sigsum.org:<prefix>"
// as origin string.  Origin string is also used as ID in the note signature.
// This means that a sigsum log's prefix (say, "glass-frog"), must be unique.
func (i *Instance) signWriteNote(w http.ResponseWriter, sth *types.SignedTreeHead) error {
	origin := fmt.Sprintf("sigsum.org:%s", i.Prefix)
	msg := fmt.Sprintf("%s\n%d\n%s\n",
		origin,
		sth.TreeSize,
		base64.StdEncoding.EncodeToString(sth.RootHash[:]),
	)
	sig, err := noteSign(i.Signer, origin, msg)
	if err != nil {
		return err
	}

	fmt.Fprintf(w, "%s\n\u2014 %s %s\n", msg, origin, sig)
	return nil
}

// noteSign returns a note signature for the provided origin and message
func noteSign(signer crypto.Signer, origin, msg string) (string, error) {
	sig, err := signer.Sign(nil, []byte(msg), crypto.Hash(0))
	if err != nil {
		return "", err
	}

	var hbuf [4]byte
	binary.BigEndian.PutUint32(hbuf[:], noteKeyHash(origin, notePubKeyEd25519(signer)))
	sig = append(hbuf[:], sig...)
	return base64.StdEncoding.EncodeToString(sig), nil
}

// See:
// https://cs.opensource.google/go/x/mod/+/refs/tags/v0.5.1:sumdb/note/note.go;l=336
func notePubKeyEd25519(signer crypto.Signer) []byte {
	return bytes.Join([][]byte{
		[]byte{algEd25519},
		signer.Public().(ed25519.PublicKey),
	}, nil)
}

// Source:
// https://cs.opensource.google/go/x/mod/+/refs/tags/v0.5.1:sumdb/note/note.go;l=222
func noteKeyHash(name string, key []byte) uint32 {
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte("\n"))
	h.Write(key)
	sum := h.Sum(nil)
	return binary.BigEndian.Uint32(sum)
}
