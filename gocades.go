package main

import (
	"fmt"
	"os"

	"github.com/akimovivan/gocades/signer"
)

func main() {
	signer := signer.NewSigner()

	data := []byte("Hello world")
	fmt.Println(len(data))
	signedData, err := signer.Sign(data)
	if err != nil {
		fmt.Printf("Error occured: %v\n", err)
	}

	os.WriteFile("signed.dat", signedData, 0777)
}
