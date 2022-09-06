package luaaesevpgolang

import (
	"encoding/base64"
	"testing"

	"github.com/forgoer/openssl"
	"github.com/stretchr/testify/assert"
)

func TestCBC128(t *testing.T) {
	secret := "shared_key!!!!!!"
	key, iv := BytesToKeyAES128CBCMD5(nil, []byte(secret))
	text := "hello world"

	// encrypt
	src := []byte(text)
	dst, _ := openssl.AesCBCEncrypt(src, key, iv, openssl.PKCS7_PADDING)
	chipertext := base64.StdEncoding.EncodeToString(dst)
	assert.Equal(t, "JGSG9q44sInxuq5q6S8Wiw==", chipertext)

	// decoded
	decodeSrc, err := base64.StdEncoding.DecodeString(chipertext)
	assert.NoError(t, err)
	dst, _ = openssl.AesCBCDecrypt(decodeSrc, key, iv, openssl.PKCS7_PADDING)
	assert.Equal(t, text, string(dst))
}
