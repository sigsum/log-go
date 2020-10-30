package stfe

import (
	"fmt"

	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	stdtls "crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io/ioutil"

	"github.com/google/certificate-transparency-go/tls"
)

// LoadTrustAnchors loads a list of PEM-encoded certificates from file
func LoadTrustAnchors(path string) ([]*x509.Certificate, *x509.CertPool, error) {
	rest, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("failed reading trust anchors: %v", err)
	}

	pool := x509.NewCertPool()
	var anchors []*x509.Certificate
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, nil, fmt.Errorf("unexpected PEM block type: %s", block.Type)
		}

		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid trust anchor before rest(%s): %v", rest, err)
		}

		anchors = append(anchors, certificate)
		pool.AddCert(certificate)
	}

	if len(anchors) == 0 {
		return nil, nil, fmt.Errorf("found no valid trust anchor in: %s", path)
	}
	return anchors, pool, nil
}

func LoadEd25519SigningKey(path string) (ed25519.PrivateKey, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed reading private key: %v", err)
	}

	var block *pem.Block
	block, data = pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("private key not loaded")
	}
	if block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("unexpected PEM block type: %s", block.Type)
	}
	if len(data) != 0 {
		return nil, fmt.Errorf("trailing data found after key: %v", data)
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed parsing signing key: %v", err)
	}

	switch t := key.(type) {
	case ed25519.PrivateKey:
		return key.(ed25519.PrivateKey), nil
	default:
		return nil, fmt.Errorf("unexpected signing key type: %v", t)
	}
}

func VerifyChain(ld *LogParameters, certificate *x509.Certificate) ([]*x509.Certificate, error) {
	opts := x509.VerifyOptions{
		Roots:     ld.AnchorPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}, // TODO: move to ld
	} // TODO: add intermediates

	chains, err := certificate.Verify(opts)
	if err != nil {
		return nil, fmt.Errorf("chain verification failed: %v", err)
	}
	if len(chains) == 0 {
		return nil, fmt.Errorf("chain verification failed: no chain")
	}
	return chains[0], nil // if we found multiple paths just pick the first one
}

func VerifySignature(leaf, signature []byte, certificate *x509.Certificate) error {
	var algo x509.SignatureAlgorithm
	switch t := certificate.PublicKey.(type) {
	case *rsa.PublicKey:
		algo = x509.SHA256WithRSA
	case *ecdsa.PublicKey:
		algo = x509.ECDSAWithSHA256
	default:
		return fmt.Errorf("unsupported public key algorithm: %v", t)
	}

	if err := certificate.CheckSignature(algo, leaf, signature); err != nil {
		return fmt.Errorf("invalid signature: %v", err)
	}
	return nil
}

func GenV1SDI(ld *LogParameters, leaf []byte) (StItem, error) {
	// Note that ed25519 does not use the passed io.Reader
	sig, err := ld.Signer.Sign(rand.Reader, leaf, crypto.Hash(0))
	if err != nil {
		return StItem{}, fmt.Errorf("ed25519 signature failed: %v", err)
	}
	return NewSignedDebugInfoV1(ld.LogId, []byte("reserved"), sig), nil
}

func GenV1STH(ld *LogParameters, th TreeHeadV1) (StItem, error) {
	serialized, err := tls.Marshal(th)
	if err != nil {
		return StItem{}, fmt.Errorf("failed tls marshaling tree head: %v", err)
	}

	// Note that ed25519 does not use the passed io.Reader
	sig, err := ld.Signer.Sign(rand.Reader, serialized, crypto.Hash(0))
	if err != nil {
		return StItem{}, fmt.Errorf("ed25519 signature failed: %v", err)
	}
	return NewSignedTreeHeadV1(th, ld.LogId, sig), nil
}

// ParseB64Chain parses a list of base64 DER-encoded X.509 certificates, such
// that the first (zero-index) string is interpretted as an end-entity
// certificate and the remaining ones as the an intermediate CertPool.
func ParseB64Chain(chain []string) (*x509.Certificate, *x509.CertPool, error) {
	var certificate *x509.Certificate
	intermediatePool := x509.NewCertPool()
	for index, cert := range chain {
		der, err := base64.StdEncoding.DecodeString(cert)
		if err != nil {
			return nil, nil, fmt.Errorf("certificate decoding failed: %v", err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, nil, fmt.Errorf("certificate decoding failed: %v", err)
		}

		if index == 0 {
			certificate = c
		} else {
			intermediatePool.AddCert(c)
		}
	}
	if certificate == nil {
		return nil, nil, fmt.Errorf("certificate chain is empty")
	}
	return certificate, intermediatePool, nil
}

func buildChainFromB64List(lp *LogParameters, b64chain []string) ([]*x509.Certificate, error) {
	certificate, _, err := ParseB64Chain(b64chain) // TODO: use intermediatePool
	if err != nil {
		return nil, err
	}

	opts := x509.VerifyOptions{
		Roots:     lp.AnchorPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}, // TODO: move to ld
	}

	chains, err := certificate.Verify(opts)
	if err != nil {
		return nil, fmt.Errorf("chain verification failed: %v", err)
	}
	if len(chains) == 0 {
		return nil, fmt.Errorf("chain verification failed: no chain")
	}

	chain := chains[0] // if we found multiple paths just pick the first one
	// TODO: check that len(chain) is OK

	return chain, nil
}

// verifySignature checks if signature is valid for some serialized data.  The
// only supported signature scheme is ecdsa_secp256r1_sha256(0x0403), see §4.3.2
// in RFC 8446.  TODO: replace ECDSA with ed25519(0x0807)
func verifySignature(_ *LogParameters, certificate *x509.Certificate, scheme stdtls.SignatureScheme, serialized, signature []byte) error {
	if scheme != stdtls.ECDSAWithP256AndSHA256 {
		return fmt.Errorf("unsupported signature scheme: %v", scheme)
	}
	if err := certificate.CheckSignature(x509.ECDSAWithSHA256, serialized, signature); err != nil {
		return fmt.Errorf("invalid signature: %v", err)
	}
	return nil
}