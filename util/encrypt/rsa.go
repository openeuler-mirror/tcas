package encrypt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
)

func GenRsaKey(bits int, path string) error {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}
	derStream := x509.MarshalPKCS1PrivateKey(privateKey)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: derStream,
	}
	err = os.MkdirAll(path, os.ModePerm)
	if err != nil {
		return err
	}
	filePrivate, err := os.Create(path + "/rsa-private.pem")
	if err != nil {
		return err
	}
	defer filePrivate.Close()
	err = pem.Encode(filePrivate, block)
	if err != nil {
		return err
	}

	publicKey := &privateKey.PublicKey
	derPkix, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return err
	}
	block = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derPkix,
	}

	filePublic, err := os.Create(path + "/rsa-public.pem")
	if err != nil {
		return err
	}
	defer filePublic.Close()
	err = pem.Encode(filePublic, block)
	if err != nil {
		return err
	}

	return nil
}
