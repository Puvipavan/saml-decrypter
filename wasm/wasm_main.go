//go:build js && wasm

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"hash"
	"syscall/js"
)

func main() {
	done := make(chan struct{})
	global := js.Global()
	global.Set("wasmDecryptAESCBC", js.FuncOf(decryptAESCBC))
	global.Set("wasmDecryptAESGCM", js.FuncOf(decryptAESGCM))
	global.Set("wasmDecryptRSA", js.FuncOf(decryptRSA))
	<-done
}

func decryptAESCBC(this js.Value, args []js.Value) any {
	if len(args) != 2 {
		return js.ValueOf(map[string]any{
			"msg":   "Number of arguments doesn't match",
			"error": true,
		})
	}

	encryptedData := args[0].String()
	key := args[1].String()

	decodedData, err := base64.StdEncoding.DecodeString(encryptedData)

	if err != nil {
		return js.ValueOf(map[string]any{
			"msg":   err.Error(),
			"error": true,
		})
	}

	decodedKey, err := base64.StdEncoding.DecodeString(key)

	if err != nil {
		return js.ValueOf(map[string]any{
			"msg":   err.Error(),
			"error": true,
		})
	}

	block, err := aes.NewCipher(decodedKey)
	if err != nil {
		return js.ValueOf(map[string]any{
			"msg":   err.Error(),
			"error": true,
		})
	}

	if len(decodedData) < aes.BlockSize {
		return js.ValueOf(map[string]any{
			"msg":   "Ciphertext too short",
			"error": true,
		})
	}

	iv := decodedData[:aes.BlockSize]
	decodedData = decodedData[aes.BlockSize:]

	if len(decodedData)%aes.BlockSize != 0 {
		return js.ValueOf(map[string]any{
			"msg":   "Ciphertext is not a multiple of the block size",
			"error": true,
		})
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(decodedData, decodedData)

	// Remove padding
	padding := int(decodedData[len(decodedData)-1])
	if padding > aes.BlockSize || padding == 0 {
		return js.ValueOf(map[string]any{
			"msg":   "Invalid padding",
			"error": true,
		})
	}

	return js.ValueOf(map[string]any{
		"msg":   "",
		"error": false,
		"data":  string(decodedData[:len(decodedData)-padding]),
	})
}

func decryptAESGCM(this js.Value, args []js.Value) any {
	if len(args) != 2 {
		return js.ValueOf(map[string]any{
			"msg":   "Number of arguments doesn't match",
			"error": true,
		})
	}

	encryptedData := args[0].String()
	key := args[1].String()

	decodedData, err := base64.StdEncoding.DecodeString(encryptedData)

	if err != nil {
		return js.ValueOf(map[string]any{
			"msg":   err.Error(),
			"error": true,
		})
	}

	decodedKey, err := base64.StdEncoding.DecodeString(key)

	if err != nil {
		return js.ValueOf(map[string]any{
			"msg":   err.Error(),
			"error": true,
		})
	}

	block, err := aes.NewCipher(decodedKey)
	if err != nil {
		return js.ValueOf(map[string]any{
			"msg":   err.Error(),
			"error": true,
		})
	}

	if len(decodedData) < 12 {
		return js.ValueOf(map[string]any{
			"msg":   "Ciphertext too short",
			"error": true,
		})
	}

	nonce := decodedData[:12]
	ciphertext := decodedData[12:]

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return js.ValueOf(map[string]any{
			"msg":   err.Error(),
			"error": true,
		})
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return js.ValueOf(map[string]any{
			"msg":   err.Error(),
			"error": true,
		})
	}

	return js.ValueOf(map[string]any{
		"msg":   "",
		"error": false,
		"data":  string(plaintext),
	})
}

func decryptRSA(this js.Value, args []js.Value) any {
	if len(args) != 4 {
		return js.ValueOf(map[string]any{
			"msg":   "Number of arguments doesn't match",
			"error": true,
		})
	}

	key := []byte(args[0].String())
	encryptedData := args[1].String()
	digest := args[2].String()
	algorithm := args[3].String()

	var hash hash.Hash

	if digest == "sha-1" {
		hash = sha1.New()
	} else if digest == "sha-256" {
		hash = sha256.New()
	} else if digest == "sha-384" {
		hash = sha512.New384()
	} else if digest == "sha-512" {
		hash = sha512.New()
	} else {
		return js.ValueOf(map[string]any{
			"msg":   "Digest algorithm is not supported",
			"error": true,
		})
	}

	block, _ := pem.Decode([]byte(key))

	if block == nil {
		return js.ValueOf(map[string]any{
			"msg":   "Invalid Private Key",
			"error": true,
		})
	}

	decodedData, err := base64.StdEncoding.DecodeString(encryptedData)

	if err != nil {
		return js.ValueOf(map[string]any{
			"msg":   err.Error(),
			"error": true,
		})
	}

	var privateKey *rsa.PrivateKey
	var decrypt []byte

	privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)

	if err != nil {
		temp, err := x509.ParsePKCS8PrivateKey(block.Bytes)

		if err != nil {
			return js.ValueOf(map[string]any{
				"msg":   "Unable to parse the private key",
				"error": true,
			})
		}

		privateKey = temp.(*rsa.PrivateKey)
	}

	if algorithm == "rsa-oaep" {
		decrypt, err = rsa.DecryptOAEP(hash, rand.Reader, privateKey, decodedData, nil)
	} else if algorithm == "rsassa-pkcs1-v1_5" {
		decrypt, err = rsa.DecryptPKCS1v15(rand.Reader, privateKey, decodedData)
	} else {
		return js.ValueOf(map[string]any{
			"msg":   "Unsupported encryption algorithm",
			"error": true,
		})
	}

	if err != nil {
		return js.ValueOf(map[string]any{
			"msg":   err.Error(),
			"error": true,
		})
	}

	return js.ValueOf(map[string]any{
		"msg":   "",
		"error": false,
		"data":  base64.StdEncoding.EncodeToString(decrypt),
	})
}
