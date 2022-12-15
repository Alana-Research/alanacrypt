package alanacrypt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type AsymmetricEncryption struct {
	Logger Logger
}

type AsymmetricEncOptions func(*AsymmetricEncryption)

func (opts *AsymmetricEncryption) log(raceSafe bool, args ...interface{}) {
	if opts.Logger != nil {
		if raceSafe {
			logMutex.Lock()
			defer logMutex.Unlock()
		}
		opts.Logger.Log(args)
	}
}

func WithLoggerForAsymmetricEnc(logger Logger) AsymmetricEncOptions {
	return func(asymEnc *AsymmetricEncryption) {
		asymEnc.Logger = logger
	}
}

func NewAssymetricEncryption(args ...AsymmetricEncOptions) (*AsymmetricEncryption, error) {
	asymEnc := &AsymmetricEncryption{
		Logger: nil,
	}

	for _, opt := range args {
		opt(asymEnc)
	}

	return asymEnc, nil
}

func (asymEnc *AsymmetricEncryption) SaveAsHEXToFile(key []byte, path string, filename string, fileExtension string) (string, error) {
	file := filepath.Join(path, filename+"."+fileExtension)
	outfile, err := os.OpenFile(file, os.O_RDWR|os.O_CREATE, 0777)
	if err != nil {
		return "", errors.New(fmt.Sprintf("Error creating file -> %s ERROR: %s", file, err.Error()))
	}
	defer outfile.Close()
	text := []byte(fmt.Sprintf(`Encrypted key in hex: %s`, ConvertByteArrayToHex(key)))

	outfile.Write(text)
	asymEnc.log(false, "Saved text -> ", text)

	if err != nil {
		return "", errors.New(fmt.Sprintf("Error writing file -> %s ERROR: %s", file, err.Error()))
	}
	return file, nil
}

func (asymEnc *AsymmetricEncryption) RSAEncrypt(keyToEncrypt []byte, pubKey string) ([]byte, error) {
	asymEnc.log(false, "AES256 key bytes length ->", len(keyToEncrypt))

	block, _ := pem.Decode([]byte(pubKey))
	if block == nil {
		return nil, errors.New("Failed to decode PEM public key")
	}

	parsedPub, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, errors.New("failed to parse PEM bytes of public key: " + err.Error())
	}

	pubEncKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, parsedPub, keyToEncrypt, []byte("encrypted."))
	if err != nil {
		return nil, err
	}

	asymEnc.log(false, "AES256 key of 32 bytes encrypted with RSA Public key ->", pubEncKey)
	asymEnc.log(false, "AES256 key 32 bytes encrypted with RSA Public key in HEX ->", ConvertByteArrayToHex(pubEncKey))
	return pubEncKey, nil
}
