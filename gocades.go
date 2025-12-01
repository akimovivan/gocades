//go:build windows || linux
// +build windows linux

package gocades

/*
#cgo windows CFLAGS: -Wall -Wno-unknown-pragmas -Wno-maybe-uninitialized -IC:/PROGRA~2/CRYPTO~1/SDK/include
#cgo windows LDFLAGS: -LC:/PROGRA~2/CRYPTO~1/SDK/lib/amd64 -lcades -lcpasn1 -lcplib -ladvapi32 -lcrypt32
#cgo linux CFLAGS: -Wall -DUNIX -I/opt/cprocsp/include/pki -I/opt/cprocsp/include/cpcsp -I/opt/cprocsp/include
#cgo linux LDFLAGS: -L/opt/cprocsp/lib/amd64 -lcades -lcapi20 -lcapi10 -lrdrsup
#include "signer.h"
#include <string.h>
*/
import "C"
import (
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"unsafe"
)

type CertInfo struct {
	CertData         []byte
	CertLength       uint32
	SubjectName      string
	SubjectLength    uint32
	HasPrivateKey    bool
	SerialNumber     []byte // hex encoded value
	SigningAlgorithm string
	Idx              int // Id of this certificate in c static array
}

// Signer provides cryptographic signing functionality using CryptoPro CAdES
type Signer struct {
	opts         *Options
	initialized  bool
	Certificates []CertInfo
	SelectedCert int
}

type Options struct {
	CertificateStore string
	HashAlgorithm    string
}

func DefaultOptions() *Options {
	return &Options{
		CertificateStore: "MY",
		HashAlgorithm:    "1.3.14.3.2.26",
	}
}

func NewSigner(opts *Options) *Signer {
	if opts == nil {
		opts = DefaultOptions()
	}

	signer := &Signer{opts: opts, initialized: false}
	runtime.SetFinalizer(signer, (*Signer).finalize)
	return signer
}

func (s *Signer) Sign(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("input data is empty")
	}

	if !s.initialized {
		return nil, errors.New("certificates are not initialized")
	}

	if len(s.Certificates) == 0 {
		return nil, errors.New("no valid certificates")
	}

	cData := (*C.uchar)(unsafe.Pointer(&data[0]))
	dataLen := C.DWORD(len(data))
	certIdx := C.uint8_t(s.SelectedCert)

	var cSignedData *C.uchar
	var signedDataLen C.DWORD

	result := C.sign_simple(cData, dataLen, &cSignedData, &signedDataLen, certIdx)

	if int(result) != 0 {
		return nil, errors.New("signing failed")
	}

	if cSignedData == nil || signedDataLen <= 0 {
		return nil, errors.New("no signed data returned")
	}

	defer C.free(unsafe.Pointer(cSignedData))

	signedData := C.GoBytes(unsafe.Pointer(cSignedData), C.int(signedDataLen))

	signedMessage := make([]byte, len(signedData))
	copy(signedMessage, signedData)

	return signedMessage, nil
}

func (s *Signer) Verify(data []byte) (bool, *CertInfo, error) {
	if len(data) == 0 {
		return false, nil, errors.New("input data is empty")
	}

	var cCertInfo C.GoCertInfo
	cData := (*C.uchar)(unsafe.Pointer(&data[0]))
	dataLen := C.DWORD(len(data))
	verificationStatus := C.BOOL(0)
	defer s.freeCertInfo(&cCertInfo)

	result := C.verify_signature(cData, dataLen, &cCertInfo, &verificationStatus)

	fmt.Printf("len of cCertInfo: %d\n", cCertInfo.cert_length)

	if result != C.SUCCESS {
		return false, nil, errors.New("failed to verify signature")
	}

	if int(verificationStatus) != 0 {
		return false, nil, nil
	}

	var certInfo CertInfo

	if cCertInfo.cert_data != nil && cCertInfo.cert_length > 0 {
		certData := C.GoBytes(unsafe.Pointer(cCertInfo.cert_data), C.int(cCertInfo.cert_length))
		certInfo.CertData = certData
		certInfo.CertLength = uint32(cCertInfo.cert_length)
	}

	if cCertInfo.serial_number != nil && cCertInfo.serial_length > 0 {
		serialBytes := C.GoBytes(unsafe.Pointer(cCertInfo.serial_number), C.int(cCertInfo.serial_length))
		certInfo.SerialNumber = serialBytes
	}

	// Convert subject name
	if cCertInfo.subject_name != nil && cCertInfo.subject_length > 0 {
		subjectBytes := C.GoBytes(unsafe.Pointer(cCertInfo.subject_name), C.int(cCertInfo.subject_length))
		certInfo.SubjectName = string(subjectBytes)
		certInfo.SubjectLength = uint32(cCertInfo.subject_length)
	}

	if cCertInfo.signing_algo != nil && cCertInfo.algo_length > 0 {
		algoBytes := C.GoBytes(unsafe.Pointer(cCertInfo.signing_algo), C.int(cCertInfo.algo_length))
		certInfo.SigningAlgorithm = string(algoBytes)
		//certInfo.SubjectLength = uint32(cCertInfo.subject_length)
	}

	certInfo.HasPrivateKey = cCertInfo.has_private_key != 0

	return true, &certInfo, nil
}

func (s *Signer) freeCertInfo(cCertInfo *C.GoCertInfo) {
	if cCertInfo.cert_data != nil {
		C.free(unsafe.Pointer(cCertInfo.cert_data))
		cCertInfo.cert_data = nil
	}
	if cCertInfo.serial_number != nil {
		C.free(unsafe.Pointer(cCertInfo.serial_number))
		cCertInfo.serial_number = nil
	}
	if cCertInfo.subject_name != nil {
		C.free(unsafe.Pointer(cCertInfo.subject_name))
		cCertInfo.subject_name = nil
	}
	if cCertInfo.signing_algo != nil {
		C.free(unsafe.Pointer(cCertInfo.signing_algo))
		cCertInfo.signing_algo = nil
	}
}

func (s *Signer) Encrypt(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("input data is empty")
	}

	cData := (*C.uchar)(unsafe.Pointer(&data[0]))
	dataLen := C.DWORD(len(data))

	var cEncrypteddData *C.uchar
	var encryptedDataLen C.DWORD

	result := C.encrypt(cData, dataLen, &cEncrypteddData, &encryptedDataLen)

	if int(result) != 0 {
		return nil, errors.New("signing failed")
	}

	if cEncrypteddData == nil || encryptedDataLen <= 0 {
		return nil, errors.New("no signed data returned")
	}

	defer C.free(unsafe.Pointer(cEncrypteddData))

	signedData := C.GoBytes(unsafe.Pointer(cEncrypteddData), C.int(encryptedDataLen))

	signedMessage := make([]byte, len(signedData))
	copy(signedMessage, signedData)

	return signedMessage, nil
}

func (s *Signer) Decrypt(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("input data is empty")
	}

	cData := (*C.uchar)(unsafe.Pointer(&data[0]))
	dataLen := C.DWORD(len(data))

	var cDecryptedData *C.uchar
	var decryptedDataLen C.DWORD

	result := C.decrypt(cData, dataLen, &cDecryptedData, &decryptedDataLen)
	if int(result) != 0 {
		slog.Error(fmt.Sprintf("failed to execute with code %d", int(result)))
		return nil, errors.New("failed to decrypt")
	}
	slog.Debug("I was here", "outLen", decryptedDataLen)

	if cDecryptedData == nil || decryptedDataLen <= 0 {
		return nil, errors.New("no signed data returned")
	}

	defer C.free(unsafe.Pointer(cDecryptedData))

	decryptedData := C.GoBytes(unsafe.Pointer(cDecryptedData), C.int(decryptedDataLen))

	decryptedMessage := make([]byte, len(decryptedData))
	copy(decryptedMessage, decryptedData)

	return decryptedMessage, nil
}

func (s *Signer) CountCertificates() int {
	count := C.count_certificates()
	return int(count)
}

func (s *Signer) InitializeCertificates() error {
	result := C.initialize_certificates()
	if result != C.SUCCESS {
		return fmt.Errorf("failed with code %d", int(result))
	}
	s.initialized = true

	count := C.count_certificates()
	certificates := make([]CertInfo, count)

	for i := range int(count) {
		cert, err := s.GetCertificateByIndex(i)
		if err != nil {
			return fmt.Errorf("failed to get certificates")
		}

		certificates[i] = *cert
	}

	s.Certificates = certificates
	return nil
}

func (s *Signer) GetCertificateByIndex(idx int) (*CertInfo, error) {
	var cCertInfo C.GoCertInfo
	defer s.freeCertInfo(&cCertInfo)

	result := C.get_certificate_by_id(C.uint8_t(idx), &cCertInfo)

	fmt.Printf("len of cCertInfo: %d\n", cCertInfo.cert_length)

	if result != C.SUCCESS {
		return nil, errors.New("failed to verify signature")
	}

	var certInfo CertInfo

	if cCertInfo.cert_data != nil && cCertInfo.cert_length > 0 {
		certData := C.GoBytes(unsafe.Pointer(cCertInfo.cert_data), C.int(cCertInfo.cert_length))
		certInfo.CertData = certData
		certInfo.CertLength = uint32(cCertInfo.cert_length)
	}

	if cCertInfo.serial_number != nil && cCertInfo.serial_length > 0 {
		serialBytes := C.GoBytes(unsafe.Pointer(cCertInfo.serial_number), C.int(cCertInfo.serial_length))
		certInfo.SerialNumber = serialBytes
	}

	// Convert subject name
	if cCertInfo.subject_name != nil && cCertInfo.subject_length > 0 {
		subjectBytes := C.GoBytes(unsafe.Pointer(cCertInfo.subject_name), C.int(cCertInfo.subject_length))
		certInfo.SubjectName = string(subjectBytes)
		certInfo.SubjectLength = uint32(cCertInfo.subject_length)
	}

	if cCertInfo.signing_algo != nil && cCertInfo.algo_length > 0 {
		algoBytes := C.GoBytes(unsafe.Pointer(cCertInfo.signing_algo), C.int(cCertInfo.algo_length))
		certInfo.SigningAlgorithm = string(algoBytes)
		//certInfo.SubjectLength = uint32(cCertInfo.subject_length)
	}

	certInfo.HasPrivateKey = cCertInfo.has_private_key != 0

	certInfo.Idx = idx

	return &certInfo, nil
}

func (s *Signer) finalize() {
	if s.initialized {
		C.clear_certificates()
	}
}
