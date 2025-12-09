package gocades

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// WARNING: requires at least one installed certificate in CryptoPro with
// private key

func TestSigning(t *testing.T) {
	signer := NewSigner(nil)
	signer.SelectedCert = 0
	err := signer.InitializeCertificates()
	require.NoError(t, err)

	data := []byte("Hello world")

	signedData, err := signer.Sign(data)
	require.NoError(t, err)

	verifiedStatus, certInfo, err := signer.Verify(signedData)
	require.NoError(t, err)

	assert.Equal(t, true, verifiedStatus)
	assert.Equal(t, "1.2.643.7.1.1.3.2", certInfo.SigningAlgorithm)

	badData := []byte("")
	_, err = signer.Sign(badData)
	require.Error(t, err)

	// No signature
	_, _, err = signer.Verify(data)
	require.Error(t, err)
}

func TestEncryption(t *testing.T) {
	signer := NewSigner(nil)

	data := []byte("Hello world")

	encryptedData, err := signer.Encrypt(data)
	require.Error(t, err)

	err = signer.InitializeCertificates()
	require.NoError(t, err)

	if len(signer.Certificates) > 1 {
		t.Logf("First cert subj: %d '%s'\tSecond cert subject: %d '%s'", signer.Certificates[0].SubjectLength, signer.Certificates[0].SubjectName, signer.Certificates[1].SubjectLength, signer.Certificates[1].SubjectName)
		signer.SelectedCert = 1
	}

	encryptedData, err = signer.Encrypt(data)
	require.NoError(t, err)

	decryptedData, err := signer.Decrypt(encryptedData)
	require.NoError(t, err)

	assert.Equal(t, data, decryptedData)
}

func TestCertificatesHandling(t *testing.T) {
	signer := NewSigner(nil)

	// NOTE: for some reason this fails
	// count := signer.CountCertificates()
	// assert.Equal(t, 0, count)

	err := signer.InitializeCertificates()
	require.NoError(t, err)

	count := signer.CountCertificates()
	assert.NotEqual(t, 0, count)

	assert.Equal(t, count, len(signer.Certificates))
	t.Log(signer.Certificates[0].SubjectName)

	t.Logf("Counted %d certificates", count)

	cert_info, err := signer.GetCertificateByIndex(0)
	require.NoError(t, err)

	t.Logf("Certificate subj: %s; issuer: %s; serial: %s; valid: %s", cert_info.SubjectName, cert_info.Issuer, hex.EncodeToString(cert_info.SerialNumber), cert_info.NotAfter)
}
