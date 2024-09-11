package encrypt

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"github.com/beego/beego/v2/core/logs"
	"golang.org/x/crypto/scrypt"
	"io"
)

func GenerateKey() (keyout string, err error) {
	salt := make([]byte, 16)
	_, err = io.ReadFull(rand.Reader, salt)
	if err != nil {
		message := fmt.Sprintf("create salt failed, error: %s", err.Error())
		logs.Error(message)
		return "", err
	}

	word := make([]byte, 10)
	_, err = rand.Read(word)
	if err != nil {
		return "", err
	}
	key, err := scrypt.Key(word, salt, 1<<15, 8, 1, 36)
	if err != nil {
		return "", err
	}

	keyout = base64.StdEncoding.EncodeToString(key)
	return keyout, nil
}
