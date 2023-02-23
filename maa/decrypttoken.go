package maa

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const aeadAdditionalData = "Transport Key"

// DecryptToken decrypts a token received from MAA.
//
// This function uses the TPM for decryption and thus it must be called on the same machine that
// created the attestation parameters via NewParameters. The PCR state must still be the same.
//
// Optionally pass an opened TPM. If tpmHandle is nil, the default TPM will be opened.
func DecryptToken(token string, tpmHandle io.ReadWriter) (string, error) {
	tpm, err := newTPM(tpmHandle)
	if err != nil {
		return "", fmt.Errorf("opening TPM: %w", err)
	}
	defer tpm.Close()
	return decryptToken(token, tpm)
}

func decryptToken(token string, tpm *tpm) (string, error) {
	// unmarhsal encrypted token
	decoded, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return "", fmt.Errorf("decoding token: %w", err)
	}
	var info encryptedTokenInfo
	if err := json.Unmarshal(decoded, &info); err != nil {
		return "", fmt.Errorf("unmarshaling token: %w", err)
	}

	// decrypt AES key
	key, err := tpm.decrypt(info.EncryptedInnerKey)
	if err != nil {
		return "", fmt.Errorf("decrypting key: %w", err)
	}

	// decrypt JWT
	aead, err := getCipher(key)
	if err != nil {
		return "", fmt.Errorf("getting cipher: %w", err)
	}
	// aead.Open panics if passing an IV with wrong length, so we must catch this ourselves
	if len(info.EncryptionParams.Iv) != aead.NonceSize() {
		return "", errors.New("invalid IV length")
	}
	jwt, err := aead.Open(nil, info.EncryptionParams.Iv, append(info.Jwt, info.AuthenticationData...), []byte(aeadAdditionalData))
	if err != nil {
		return "", fmt.Errorf("decrypting JWT: %w", err)
	}

	return string(jwt), nil
}

func getCipher(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

type encryptedTokenInfo struct {
	Jwt                []byte
	EncryptedInnerKey  []byte
	EncryptionParams   encryptionParams
	AuthenticationData []byte
}

type encryptionParams struct {
	Iv []byte
}
