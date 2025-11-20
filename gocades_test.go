package gocades_test

import (
	"testing"

	cades "github.com/akimovivan/gocades"
)

func TestSigning(t *testing.T) {
	data := []byte("Hello, World!")

	signature, err := cades.SignSimple(data)
	if err != nil {
		t.Errorf("Simple signing failed: %v", err)
	}
	t.Logf("Simple signature: %d bytes\n", len(signature))

	signer := cades.NewSignerWithOptions(&cades.Options{
		CertificateStore: "MY",
		HashAlgorithm:    "1.3.14.3.2.26",
	})

	info, err := signer.GetSignerInfo()
	if err != nil {
		t.Errorf("Failed to get signer info: %v", err)
	}
	t.Logf("Certificates found: %d, Has private key: %v\n",
		info.CertificateCount, info.HasPrivateKey)

	signature2, err := signer.Sign(data)
	if err != nil {
		t.Errorf("Signing failed: %v", err)
	}
	t.Logf("Advanced signature: %d bytes\n", len(signature2))
}

func TestSigningFromExample(t *testing.T) {
	data := []byte("Hello, World!")
	signedMessage, err := cades.SignFromExample(data)
	if err != nil {
		t.Errorf("failed to sign message: %v", err)
	}

	t.Logf("Signed message: %s", string(signedMessage))
}

// func TestVerification(t *testing.T) {
// 	data := []byte("Hello")
// 	signature, err := cades.SignSimple(data)
// 	if err != nil {
// 		t.Errorf("Failed with %v", err)
// 	}
// 	err = cades.SignVerify(signature)
// 	if err != nil {
// 		t.Errorf("Failed with %v", err)
// 	}
// 	t.Logf("verification successfull")
// }
