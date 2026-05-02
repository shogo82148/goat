// openssl_test.go tests the compatibility with OpenSSL.
// These tests require OpenSSL to be installed, and will be skipped if OpenSSL doesn't support secp256k1.

package secp256k1

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
)

var publicKeyOID = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
var curveOID = asn1.ObjectIdentifier{1, 3, 132, 0, 10}

type ecPrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

type keyMeta struct {
	KeyType       asn1.ObjectIdentifier
	NamedCurveOID asn1.ObjectIdentifier
}

type ecPublicKey struct {
	KeyMeta   keyMeta
	PublicKey asn1.BitString
}

func TestVerify_OpenSSL(t *testing.T) {
	// integration test with OpenSSL
	// generate signature using OpenSSL, and verify it using goat.
	checkSecp256k1Support(t)

	for i := range 1024 {
		t.Run(strconv.Itoa(i), testVerifyOpenSSL)
	}
}

func testVerifyOpenSSL(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	// generate a private key
	priv := GenerateKey()
	pub := priv.PublicKey()
	privateKeyPath := filepath.Join(dir, "private-key.pem")
	if err := writePrivateKey(privateKeyPath, priv); err != nil {
		t.Error(err)
		return
	}

	// generate a message
	message := make([]byte, 1024)
	if _, err := rand.Read(message); err != nil {
		t.Error(err)
		return
	}
	messagePath := filepath.Join(dir, "message.txt")
	if err := os.WriteFile(messagePath, message, 0o644); err != nil {
		t.Error(err)
		return
	}

	// sign
	sig, err := signWithOpenSSL(privateKeyPath, messagePath)
	if err != nil {
		t.Error(err)
		return
	}

	sum := sha256.Sum256(message)
	if !VerifyASN1(pub, sum[:], sig) {
		t.Errorf("verify failed:\nmessage: %q", message)
	}
}

func TestSign_OpenSSL(t *testing.T) {
	// integration test with OpenSSL
	// generate signature using goat, and verify it using OpenSSL.
	checkSecp256k1Support(t)

	for i := range 1024 {
		t.Run(strconv.Itoa(i), testSignOpenSSL)
	}
}

func testSignOpenSSL(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	// generate a private key
	priv := GenerateKey()
	pub := priv.PublicKey()
	publicKeyPath := filepath.Join(dir, "public-key.pem")
	if err := writePublicKey(publicKeyPath, pub); err != nil {
		t.Error(err)
		return
	}

	// generate a message
	message := make([]byte, 1024)
	if _, err := rand.Read(message); err != nil {
		t.Error(err)
		return
	}
	messagePath := filepath.Join(dir, "message.txt")
	if err := os.WriteFile(messagePath, message, 0o644); err != nil {
		t.Error(err)
		return
	}

	// calculate signature
	sum := sha256.Sum256(message)
	sig, err := SignASN1(priv, sum[:])
	if err != nil {
		t.Error(err)
		return
	}
	signaturePath := filepath.Join(dir, "message.sig")
	if err := writeSignature(signaturePath, sig); err != nil {
		t.Error(err)
		return
	}

	// verify
	if err := verifyWithOpenSSL(publicKeyPath, signaturePath, messagePath); err != nil {
		t.Errorf("verify failed: %v\nmessage: %q\n", err, message)
	}
}

func checkSecp256k1Support(t *testing.T) bool {
	out, err := exec.Command("openssl", "ecparam", "-list_curves").CombinedOutput()
	if err != nil {
		t.Skip(err)
		return false
	}
	found := bytes.Contains(out, []byte("secp256k1"))
	if !found {
		t.Skip("OpenSSL doesn't support secp256k1")
		return false
	}
	return true
}

func signWithOpenSSL(privateKeyPath, messagePath string) (sig []byte, err error) {
	out, err := exec.Command("openssl", "dgst", "-sha256", "-sign", privateKeyPath, messagePath).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%w: %s", err, out)
	}
	return out, nil
}

func verifyWithOpenSSL(pubkeyPath, signaturePath, messagePath string) error {
	out, err := exec.Command("openssl", "dgst", "-sha256", "-verify", pubkeyPath, "-signature", signaturePath, messagePath).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, out)
	}
	return nil
}

func writePrivateKey(name string, key *PrivateKey) error {
	pub := key.PublicKey()
	d := key.d[:]
	buf, err := pub.Bytes()
	if err != nil {
		return err
	}

	priv := ecPrivateKey{
		Version:       1,
		PrivateKey:    d,
		NamedCurveOID: curveOID,
		PublicKey: asn1.BitString{
			Bytes: buf,
		},
	}
	data, err := asn1.Marshal(priv)
	if err != nil {
		return err
	}
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: data,
	})
	return os.WriteFile(name, pemData, 0o600)
}

func writePublicKey(name string, key *PublicKey) error {
	buf, err := key.Bytes()
	if err != nil {
		return err
	}

	pub := ecPublicKey{
		KeyMeta: keyMeta{
			KeyType:       publicKeyOID,
			NamedCurveOID: curveOID,
		},
		PublicKey: asn1.BitString{
			Bytes: buf,
		},
	}
	data, err := asn1.Marshal(pub)
	if err != nil {
		return err
	}
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: data,
	})
	return os.WriteFile(name, pemData, 0o644)
}

func writeSignature(name string, sig []byte) error {
	return os.WriteFile(name, sig, 0o644)
}
