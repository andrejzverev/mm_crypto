package crypto_test

import (
	"testing"

	mm_crypto "github.com/andrejzverev/mm_crypto"
)

func TestCreateNewKeys(t *testing.T) {
	r := mm_crypto.RsaKeys{}
	err := r.GenerateKey(2048)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

}

func TestEncodePrivateKeyPEM(t *testing.T) {
	r := mm_crypto.RsaKeys{}
	err := r.GenerateKey(2048)
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	b := r.EncodePrivateKeyPEM()
	if len(b) < 10 {
		t.Fatalf("can not encode privatekey to PEM format")
	}
}

func TestEncodePublicKeyPEM(t *testing.T) {
	r := mm_crypto.RsaKeys{}
	err := r.GenerateKey(2048)
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	b, err := r.EncodePublicKeyPEM()
	if len(b) < 10 || err != nil {
		t.Fatalf("can not encode public to PEM format %s", err)
	}
}
