package main 

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
)

func HexEncode(data []byte) string {
	return hex.EncodeToString(data)
}

func HexDecode(data string) []byte {
	res, err := hex.DecodeString(data)
	if err != nil {
		return nil
	}
	return res
}

func DecryptRSA(priv *rsa.PrivateKey, data []byte) []byte {
	data, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, priv, data, nil)
	if err != nil {
		return nil
	}
	return data
}

func DecryptAES(key, data []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	blockSize := block.BlockSize()
	if len(data) < blockSize {
		return nil
	}
	iv := data[:blockSize]
	data = data[blockSize:]
	if len(data)%blockSize != 0 {
		return nil
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(data, data)
	return unpaddingPKCS5(data)
}

func unpaddingPKCS5(origData []byte) []byte {
	length := len(origData)
	if length == 0 {
		return nil
	}
	unpadding := int(origData[length-1])
	if length < unpadding {
		return nil
	}
	return origData[:(length - unpadding)]
}

func ParsePrivate(privData []byte) *rsa.PrivateKey {
	block, _ := pem.Decode(privData)
	if block == nil {
		return nil
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil
	}
	return priv
}

func BytesPrivate(priv *rsa.PrivateKey) []byte {
	bytes := x509.MarshalPKCS1PrivateKey(priv)
	privData := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: bytes,
		},
	)
	return privData
}

func BytesPublic(pub *rsa.PublicKey) []byte {
	bytes := x509.MarshalPKCS1PublicKey(pub)
	pubData := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: bytes,
		},
	)
	return pubData
}

func HashPublic(pub *rsa.PublicKey) string {
	return HexEncode(HashSum(BytesPublic(pub)))
}

func HashSum(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}