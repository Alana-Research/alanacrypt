package alanacrypt

import (
	"encoding/hex"
	"io/fs"
	"path/filepath"
)

func ConvertHexToByteArray(hexa string) ([]byte, error) {
	decodedByteArray, err := hex.DecodeString(hexa)
	if err != nil {
		return nil, err
	}
	return decodedByteArray, nil
}

func ConvertByteArrayToHex(arr []byte) string {
	return hex.EncodeToString(arr)
}

func ConvertByteArrayToString(arr []byte) string {
	return string(arr[:])
}

func GetFiles(rootPath string) []string {
	var paths []string
	filepath.WalkDir(rootPath, func(path string, di fs.DirEntry, err error) error {
		if !di.IsDir() {
			paths = append(paths, path)
		}
		return nil
	})

	return paths
}
