package alanacrypt

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

func (asymEnc *AsymmetricEncryption) RetrieveAndDecryptEncKeyFromFile(filePath string, rsa_private_key_path string) ([]byte, error) {
	//retrieve key in bytes reading the .pem key file
	privateKeyString, err := ioutil.ReadFile(rsa_private_key_path)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Error opening rsa private key -> %s", err.Error()))
	}

	block, _ := pem.Decode([]byte(privateKeyString))
	privateKey, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
	asymEnc.log(false, "RSA private key readed ->", privateKey.N)

	file, err := os.Open(filePath)
	if err != nil {
		return nil, errors.New("Error opening file to get the key -> " + err.Error())
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if err := scanner.Err(); err != nil {
			return nil, errors.New("Error reading lines in file to get the key -> " + err.Error())
		}
		if strings.Contains(line, "Encrypted key in hex:") {
			encryptedKey, err := ConvertHexToByteArray(strings.Split(line, ": ")[1])
			if err != nil {
				return nil, errors.New("Error converting hex encrypted key to []byte -> " + err.Error())
			}
			asymEnc.log(false, "Encrypted key on file: ", encryptedKey)

			//decrypt that with the private key retrieved at the beginning
			decryptedmsg, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, encryptedKey, []byte("encrypted."))
			if err != nil {
				return nil, errors.New("Error decrypting rsa key -> " + err.Error())
			}
			asymEnc.log(false, "Decrypted key on file: ", decryptedmsg)

			return decryptedmsg, nil
		}
	}

	return nil, errors.New("Error: the file had been altered.")
}
