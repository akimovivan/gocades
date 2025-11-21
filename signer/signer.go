package signer

/*
#cgo LDFLAGS: -L. -lsigner
#include "libsigner.h"
#include <stdlib.h>
*/
import "C"
import (
	"errors"
	"unsafe"
)

type Signer struct{}

func NewSigner() *Signer {
	return &Signer{}
}

func (s *Signer) Sign(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("input data is empty")
	}

	cData := (*C.uchar)(unsafe.Pointer(&data[0]))
	dataLen := C.int(len(data))

	var cSignedData *C.uchar
	var signedDataLen C.int

	result := C.sign_simple_wrapper(cData, dataLen, &cSignedData, &signedDataLen)

	if int(result) != 0 {
		return nil, errors.New("signing failed")
	}

	if cSignedData == nil || signedDataLen <= 0 {
		return nil, errors.New("no signed data returned")
	}

	defer C.free(unsafe.Pointer(cSignedData))

	signedData := C.GoBytes(unsafe.Pointer(cSignedData), signedDataLen)

	signedMessage := make([]byte, len(signedData))
	copy(signedMessage, signedData)

	return signedMessage, nil
}
