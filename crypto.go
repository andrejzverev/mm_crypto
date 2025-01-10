package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
)

type RsaKeys struct {
	privateKey *rsa.PrivateKey
}

func (r *RsaKeys) GenerateKey(keybits int) error {
	if r.privateKey != nil {
		return fmt.Errorf("rsa keypair already created")
	}
	privKey, err := rsa.GenerateKey(rand.Reader, keybits)
	if err != nil {
		return fmt.Errorf("unable to create rsa keypair: %s", err)
	}

	r.privateKey = privKey
	return nil

}

// Decode private key from PEM format
func (r *RsaKeys) ImportPrivateKeyPEM(pemBody []byte) error {
	var privateKeyBlock *pem.Block

	privateKeyBlock, _ = pem.Decode(pemBody)
	privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		return err
	}
	r.privateKey = privateKey
	return nil
}

// Encode the private key to the PEM format
func (r *RsaKeys) EncodePrivateKeyPEM() []byte {
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(r.privateKey)
	privateKeyBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	}
	return pem.EncodeToMemory(privateKeyBlock)

}

// Encode the public key to the PEM format
func (r *RsaKeys) EncodePublicKeyPEM() ([]byte, error) {
	publicKey := &r.privateKey.PublicKey
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	return pem.EncodeToMemory(publicKeyBlock), nil
}

func (r *RsaKeys) SignPayloadSha512(data []byte) ([]byte, error) {

	licenseBody, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	licenseHash := sha512.New()
	_, err = licenseHash.Write(licenseBody)
	if err != nil {
		return nil, err
	}

	licenseBodyHash := licenseHash.Sum(nil)
	signature, err := rsa.SignPKCS1v15(rand.Reader, r.privateKey, crypto.SHA512, licenseBodyHash)
	return append(licenseBody, signature...), nil
}
