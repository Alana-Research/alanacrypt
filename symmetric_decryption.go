package alanacrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
)

func NewFolderDecryption(encryptedPath string, opts ...EncOptions) (*FolderEncryption, error) {
	dec := &FolderEncryption{
		Folder:       encryptedPath,
		BufferSize:   DEFAULT_BUFFER_SIZE,
		SymmetricKey: nil,
		Logger:       nil,
	}

	for _, opt := range opts {
		opt(dec)
	}

	if dec.SymmetricKey == nil {
		return nil, errors.New("FolderEncryption.SymmetricKey cannot be nil.")
	}

	return dec, nil
}

func FileDecryption(filePath string, aesKey []byte, bufferSize int, fileExtension string) error {
	encfile, err := os.Open(filePath)
	if err != nil {
		return errors.New(fmt.Sprintf("Decryption FAILED at opening file -> %s ERROR: %s", filePath, err.Error()))
	}

	outfile, err := os.OpenFile(removeEncryptionExtension(filePath, fileExtension), os.O_RDWR|os.O_CREATE, 0777)
	if err != nil {
		return errors.New(fmt.Sprintf("Decryption FAILED at opening file -> %s ERROR: %s", removeEncryptionExtension(filePath, fileExtension), err.Error()))
	}
	defer encfile.Close()
	defer outfile.Close()

	cipehrBlock, err := aes.NewCipher(aesKey)
	if err != nil {
		return errors.New(fmt.Sprintf("Decryption FAILED at creating cyper block -> ERROR: %s", err.Error()))
	}

	endFile, err := encfile.Stat()
	if err != nil {
		return errors.New(fmt.Sprintf("Decryption FAILED at getting file stats -> ERROR: %s", err.Error()))
	}

	iv := make([]byte, cipehrBlock.BlockSize())
	ivLength := endFile.Size() - int64(len(iv))
	_, err = encfile.ReadAt(iv, ivLength)
	if err != nil {
		return errors.New(fmt.Sprintf("Decryption FAILED at reading IV -> ERROR: %s", err.Error()))
	}

	buffer := make([]byte, bufferSize)
	stream := cipher.NewCTR(cipehrBlock, iv)
	var errorDecrypting error = nil

	for {
		bytePosition, err := encfile.Read(buffer)
		if err == io.EOF {
			break
		}
		if err != nil {
			errorDecrypting = err
			break
		}

		if bytePosition > int(ivLength) {
			bytePosition = int(ivLength)
		}
		ivLength -= int64(bytePosition)
		stream.XORKeyStream(buffer, buffer[:bytePosition])
		outfile.Write(buffer[:bytePosition])
		if err != nil {
			errorDecrypting = err
			break
		}
	}

	return errorDecrypting
}

func (opts *FolderEncryption) DecryptFiles() (int64, error) {
	opts.log(false, "Trying to decrypt with:", opts.SymmetricKey)
	opts.log(false, "Decrypting root path:", opts.Folder)

	files := GetFiles(opts.Folder)

	var totalFilesDecrypted int64 = 0
	var wg sync.WaitGroup
	wg.Add(len(files))
	totalFiles := len(files)
	opts.log(false, "Started decryption:")
	for _, file := range files {
		go func(file string) {
			err := FileDecryption(file, opts.SymmetricKey, opts.BufferSize, opts.FileExtension)
			if err != nil {
				opts.log(true, "Failed decrypting file ->", file, err.Error())
			} else {
				opts.log(true, "Success decrypting file ->", file)
				err = os.Remove(file)
				if err != nil {
					opts.log(true, "Failed removing encripted file after decryption ->", file)
				} else {
					atomic.AddInt64(&totalFilesDecrypted, 1)
				}
			}
			wg.Done()
		}(file)
	}

	wg.Wait()
	opts.log(false, fmt.Sprintf("Finished decryption of %d files from %d", totalFilesDecrypted, totalFiles))

	return totalFilesDecrypted, nil
}

func removeEncryptionExtension(filename string, fileExtension string) string {
	return strings.Split(filename, "."+fileExtension)[0]
}
