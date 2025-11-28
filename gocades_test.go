package gocades

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestSigning(t *testing.T) {
	signer := NewSigner()

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
