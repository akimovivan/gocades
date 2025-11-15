//go:build linux || windows

package gocades

/*
#cgo linux CFLAGS: -DUNIX -I/opt/cprocsp/include/pki -I/opt/cprocsp/include/cpcsp -I/opt/cprocsp/include
#cgo linux LDFLAGS: -L/opt/cprocsp/lib/amd64 -lcades -lcapi20 -lcapi10 -lrdrsup
#cgo windows CFLAGS: -IC:/Progra~2/Crypto~1/SDK/include
#cgo windows LDFLAGS: -LC:/Progra~2/Crypto~1/SDK/lib/amd64 -Wl,-Bstatic -lcades -lcrypt32 -lws2_32 -lstdc++ -lgcc -Wl,-Bdynamic
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

	// Convert Go options to C strings
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
	default:
		return fmt.Errorf("crypto pro error (code %d)", code)
	}
}
