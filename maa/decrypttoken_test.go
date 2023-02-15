package maa

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecryptToken(t *testing.T) {
	requir := require.New(t)

	const gcmTagSize = 16
	plaintext := "plaintext"

	// create the ciphertext
	aesKey := make([]byte, 16)
	aead, err := getCipher(aesKey)
	requir.NoError(err)
	iv := make([]byte, aead.NonceSize())
	ciphertext := aead.Seal(nil, iv, []byte(plaintext), []byte(aeadAdditionalData))
	// Go Implementation appends the GCM tag, MAA protocol wants this as different fields
	jwt, authTag := ciphertext[:len(ciphertext)-gcmTagSize], ciphertext[len(ciphertext)-gcmTagSize:]

	// prepare TPM
	sim, err := newSimTPM()
	requir.NoError(err)
	defer sim.Close()
	tpm := &tpm{sim}

	// encrypt AES key with the public encryption key from the TPM
	pubKey, err := tpm.getEncryptionPubKey()
	requir.NoError(err)
	encryptedAESKey, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey.(*rsa.PublicKey), aesKey)
	requir.NoError(err)

	testCases := map[string]struct {
		info    encryptedTokenInfo
		wantErr bool
	}{
		"valid encryption": {
			info: encryptedTokenInfo{
				Jwt:                jwt,
				EncryptedInnerKey:  encryptedAESKey,
				EncryptionParams:   encryptionParams{iv},
				AuthenticationData: authTag,
			},
		},
		"invalid IV": {
			info: encryptedTokenInfo{
				Jwt:                jwt,
				EncryptedInnerKey:  encryptedAESKey,
				EncryptionParams:   encryptionParams{make([]byte, aead.NonceSize()+2)},
				AuthenticationData: authTag,
			},
			wantErr: true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)

			marshaled, err := json.Marshal(tc.info)
			require.NoError(err)
			token := base64.RawURLEncoding.EncodeToString(marshaled)

			decrypted, err := decryptToken(token, tpm)
			if tc.wantErr {
				assert.Error(err)
				return
			}
			require.NoError(err)

			assert.Equal(plaintext, decrypted)
		})
	}
}
