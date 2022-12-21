# alana-crypt module

Golang module used in Alana Research encryption related projects.

## Example

```go
// Example folder encrypt
al, _ := alanacrypt.NewFolderEncryption("/path/to/encrypt", "myExtension")
al.Encrypt()

//Example folder decrypt
al, _ := alanacrypt.NewFolderEncryption("/path/encrypted", "encryptedExtension", alanacrypt.WithEncryptionKey(keyDec))
al.DecryptFiles()

//It uses the functional options patter so you can modfify file read buffer size and add your own logger:
alanacrypt.WithBufferSize(8192)
alanacrypt.WithLogger(alanacrypt.LoggerFunc(func(args ...interface{}) {
  //your custom logger
	tlog.Warn(args...)
})
```


```go
//Asymmetric encryption and decryption example
asym, _ := alanacrypt.NewAssymetricEncryption(
	alanacrypt.WithLoggerForAsymmetricEnc(alanacrypt.LoggerFunc(func(args ...interface{}) {
		tlog.Info(args...)
})))

keyDec, err := asym.RetrieveAndDecryptEncKeyFromFile("./keySaved.txt", private_key_file)
keyEnc, err := asym.RSAEncrypt(key, RSA4096PubKeyString)
pathSaved, err := asym.SaveAsHEXToFile(keyEnc, "./", "keySaved", "txt")
```

## TODO:

- implement tests
- Implement a context to cancel encryption https://www.digitalocean.com/community/tutorials/how-to-use-contexts-in-go
