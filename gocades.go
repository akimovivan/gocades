//go:build linux
// +build linux

package gocades

/*
#cgo CFLAGS: -DUNIX -I/opt/cprocsp/include/pki -I/opt/cprocsp/include/cpcsp -I/opt/cprocsp/include
#cgo LDFLAGS: -L/opt/cprocsp/lib/amd64 -lcades -lcapi20 -lcapi10 -lrdrsup
#include "signer.h"
*/
import "C"
import (
	"errors"
	"fmt"
	"unsafe"
)

// Signer provides cryptographic signing functionality using CryptoPro CAdES
type Signer struct {
	opts *Options
}

// Options configures the signer behavior
type Options struct {
	// CertificateStore specifies the system store to use (default: "MY")
	CertificateStore string
	// HashAlgorithm specifies the hash algorithm (default: "1.3.14.3.2.26" - SHA1)
	HashAlgorithm string
}

// DefaultOptions returns the default signing options
func DefaultOptions() *Options {
	return &Options{
		CertificateStore: "MY",
		HashAlgorithm:    "1.3.14.3.2.26", // SHA1
	}
}

// NewSigner creates a new signer with default options
func NewSigner() *Signer {
	return &Signer{
		opts: DefaultOptions(),
	}
}

// NewSignerWithOptions creates a new signer with custom options
func NewSignerWithOptions(opts *Options) *Signer {
	if opts == nil {
		opts = DefaultOptions()
	}
	return &Signer{opts: opts}
}

// Sign signs the input data using CryptoPro CAdES
func (s *Signer) Sign(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("data cannot be empty")
	}

	var (
		outSig *C.uchar
		outLen C.int
	)

	cStore := C.CString(s.opts.CertificateStore)
	cHashAlg := C.CString(s.opts.HashAlgorithm)
	defer func() {
		C.free(unsafe.Pointer(cStore))
		C.free(unsafe.Pointer(cHashAlg))
	}()

	result := C.cades_sign_with_options(
		(*C.char)(unsafe.Pointer(&data[0])),
		C.int(len(data)),
		cStore,
		cHashAlg,
		&outSig,
		&outLen,
	)

	if result != 0 {
		return nil, mapError(result)
	}

	// Ensure C memory is freed, even if GoBytes panics
	signature := C.GoBytes(unsafe.Pointer(outSig), outLen)
	C.free(unsafe.Pointer(outSig))

	return signature, nil
}

// SignSimple is a convenience function for simple signing with default options
func SignSimple(data []byte) ([]byte, error) {
	signer := NewSigner()
	return signer.Sign(data)
}

// GetSignerInfo returns information about available certificates
func (s *Signer) GetSignerInfo() (*SignerInfo, error) {
	var info C.SignerInfo
	result := C.get_signer_info(&info)
	if result != 0 {
		return nil, mapError(result)
	}

	hasPrivateKey := false
	if info.has_private_key > 0 {
		hasPrivateKey = true
	}

	return &SignerInfo{
		CertificateCount: int(info.certificate_count),
		HasPrivateKey:    hasPrivateKey,
	}, nil
}

// SignerInfo contains information about available signing certificates
type SignerInfo struct {
	CertificateCount int
	HasPrivateKey    bool
}

// VerificationResult represents the result of signature verification
type VerificationResult struct {
	Verified     bool
	Status       int
	ErrorMessage string
}

// VerifySignature verifies a CAdES signature and returns detailed results
func (s *Signer) VerifySignature(signedMessage []byte) (*VerificationResult, error) {
	if len(signedMessage) == 0 {
		return nil, errors.New("signed message cannot be empty")
	}

	cSignedMessage := C.CString(string(signedMessage))
	defer C.free(unsafe.Pointer(cSignedMessage))

	var cResult C.VerificationResult
	defer C.free_verification_result(&cResult)

	resultCode := C.cades_verify_message(cSignedMessage, &cResult)

	if resultCode != 0 {
		return nil, fmt.Errorf("verification failed with code %d", resultCode)
	}

	isVerified := false
	if cResult.verified > 0 {
		isVerified = true
	}
	goResult := &VerificationResult{
		Verified: bool(isVerified),
		Status:   int(cResult.status),
	}

	if cResult.error_message != nil {
		goResult.ErrorMessage = C.GoString(cResult.error_message)
	}

	return goResult, nil
}

// VerifySignatureSimple provides a simple boolean verification result
func (s *Signer) VerifySignatureSimple(signedMessage []byte) (bool, error) {

	result, err := s.VerifySignature(signedMessage)
	if err != nil {
		return false, err
	}
	return result.Verified, nil
}

// VerifySignatureString verifies a signature from a string
func (s *Signer) VerifySignatureString(signedMessage string) (*VerificationResult, error) {
	return s.VerifySignature([]byte(signedMessage))
}

// SimpleVerify is a convenience function for simple verification
func SimpleVerify(signedMessage []byte) (bool, error) {
	signer := NewSigner()
	return signer.VerifySignatureSimple(signedMessage)
}

// Your original C function wrapper (returns simple success/failure)
func SignVerify(signedMessage []byte) error {
	if len(signedMessage) == 0 {
		return errors.New("signed message cannot be empty")
	}

	cSignedMessage := C.CString(string(signedMessage))
	defer C.free(unsafe.Pointer(cSignedMessage))

	result := C.sign_verify(cSignedMessage, C.int(len(signedMessage)))

	switch result {
	case 0:
		return nil // Success
	case 1:
		return errors.New("CadesVerifyMessage failed")
	case 2:
		return errors.New("CadesFreeVerificationInfo failed")
	case 3:
		return errors.New("CadesFreeBlob failed")
	case 4:
		return errors.New("signature verification failed")
	default:
		return fmt.Errorf("unknown verification error: %d", result)
	}
}

// Add to your existing mapError function
func mapError(code C.int) error {
	switch code {
	case -1:
		return errors.New("invalid input parameters")
	case -2:
		return errors.New("failed to open certificate store")
	case -3:
		return errors.New("no valid certificate with private key found")
	case -4:
		return errors.New("failed to get signature size")
	case -5:
		return errors.New("memory allocation failed")
	case -6:
		return errors.New("signing operation failed")
	case -7:
		return errors.New("failed to copy signature")
	// Add verification errors
	case -8:
		return errors.New("verification failed - CadesVerifyMessage error")
	case -9:
		return errors.New("verification failed - memory cleanup error")
	case -10:
		return errors.New("verification failed - blob cleanup error")
	default:
		return fmt.Errorf("crypto pro error (code %d)", code)
	}
}
