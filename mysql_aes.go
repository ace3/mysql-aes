// Package mysql_aes provides MySQL-compatible AES encryption and decryption functionality.
// This library ensures that data encrypted in Go can be decrypted using MySQL's AES_DECRYPT
// function and vice versa, maintaining full compatibility between application-level and
// database-level operations.
package mysql_aes

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"strconv"
)

const (
	// AESKeyLen defines the AES key length in bits (128-bit)
	AESKeyLen = 128
	// BlockSize is the AES block size in bytes
	BlockSize = aes.BlockSize
)

// MySQLAES provides MySQL-compatible AES encryption and decryption operations
type MySQLAES struct{}

// New creates a new MySQLAES instance
func New() *MySQLAES {
	return &MySQLAES{}
}

// aesKey processes the key to match MySQL's key handling behavior.
// MySQL wraps keys longer than 16 bytes back into the 16-byte key array using XOR.
func (m *MySQLAES) aesKey(key []byte) []byte {
	const keyLen = AESKeyLen / 8 // 16 bytes for 128-bit key

	if len(key) == keyLen {
		return key
	}

	k := make([]byte, keyLen)
	copy(k, key)
	
	// XOR wrap-around for keys longer than 16 bytes
	for i := keyLen; i < len(key); {
		for j := 0; j < keyLen && i < len(key); j, i = j+1, i+1 {
			k[j] ^= key[i]
		}
	}
	return k
}

// Encrypt encrypts plaintext using AES-ECB mode, compatible with MySQL's AES_ENCRYPT function
func (m *MySQLAES) Encrypt(plaintext, key []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("plaintext cannot be empty")
	}
	if len(key) == 0 {
		return nil, fmt.Errorf("key cannot be empty")
	}

	processedKey := m.aesKey(key)
	block, err := aes.NewCipher(processedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Apply PKCS7 padding
	paddedText := m.pkcs7Pad(plaintext, BlockSize)
	
	// Encrypt using ECB mode
	ciphertext := make([]byte, len(paddedText))
	for i := 0; i < len(paddedText); i += BlockSize {
		block.Encrypt(ciphertext[i:i+BlockSize], paddedText[i:i+BlockSize])
	}

	return ciphertext, nil
}

// Decrypt decrypts ciphertext using AES-ECB mode, compatible with MySQL's AES_DECRYPT function
func (m *MySQLAES) Decrypt(ciphertext, key []byte) ([]byte, error) {
	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("ciphertext cannot be empty")
	}
	if len(key) == 0 {
		return nil, fmt.Errorf("key cannot be empty")
	}
	if len(ciphertext)%BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext length must be multiple of block size")
	}

	processedKey := m.aesKey(key)
	block, err := aes.NewCipher(processedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Decrypt using ECB mode
	plaintext := make([]byte, len(ciphertext))
	for i := 0; i < len(ciphertext); i += BlockSize {
		block.Decrypt(plaintext[i:i+BlockSize], ciphertext[i:i+BlockSize])
	}

	// Remove PKCS7 padding
	unpaddedText, err := m.pkcs7Unpad(plaintext)
	if err != nil {
		return nil, fmt.Errorf("failed to remove padding: %w", err)
	}

	return unpaddedText, nil
}

// EncryptString encrypts a string and returns the result as a hex string
func (m *MySQLAES) EncryptString(plaintext, key string) (string, error) {
	encrypted, err := m.Encrypt([]byte(plaintext), []byte(key))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(encrypted), nil
}

// DecryptString decrypts a hex string and returns the result as a string
func (m *MySQLAES) DecryptString(ciphertextHex, key string) (string, error) {
	ciphertext, err := hex.DecodeString(ciphertextHex)
	if err != nil {
		return "", fmt.Errorf("invalid hex string: %w", err)
	}
	
	decrypted, err := m.Decrypt(ciphertext, []byte(key))
	if err != nil {
		return "", err
	}
	
	return string(decrypted), nil
}

// pkcs7Pad applies PKCS7 padding to the data
func (m *MySQLAES) pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := make([]byte, padding)
	for i := range padText {
		padText[i] = byte(padding)
	}
	return append(data, padText...)
}

// pkcs7Unpad removes PKCS7 padding from the data
func (m *MySQLAES) pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("data is empty")
	}
	
	padding := int(data[len(data)-1])
	if padding == 0 || padding > len(data) {
		return nil, fmt.Errorf("invalid padding")
	}
	
	// Verify padding
	for i := len(data) - padding; i < len(data); i++ {
		if data[i] != byte(padding) {
			return nil, fmt.Errorf("invalid padding")
		}
	}
	
	return data[:len(data)-padding], nil
}

// UserKeyDeriver provides functionality for deriving user-specific encryption keys
type UserKeyDeriver struct {
	baseKey    string
	masterSalt string
}

// NewUserKeyDeriver creates a new UserKeyDeriver with base configuration
func NewUserKeyDeriver(baseKey, masterSalt string) *UserKeyDeriver {
	return &UserKeyDeriver{
		baseKey:    baseKey,
		masterSalt: masterSalt,
	}
}

// DeriveUserKey derives a user-specific encryption key using the formula: baseKey + userID + ":" + masterSalt
func (ukd *UserKeyDeriver) DeriveUserKey(userID interface{}) string {
	var userIDStr string
	switch v := userID.(type) {
	case uint:
		userIDStr = strconv.FormatUint(uint64(v), 10)
	case uint64:
		userIDStr = strconv.FormatUint(v, 10)
	case int:
		userIDStr = strconv.Itoa(v)
	case int64:
		userIDStr = strconv.FormatInt(v, 10)
	case string:
		userIDStr = v
	default:
		userIDStr = fmt.Sprintf("%v", userID)
	}
	
	return ukd.baseKey + userIDStr + ":" + ukd.masterSalt
}

// EncryptForUser encrypts data for a specific user using a derived key
func (ukd *UserKeyDeriver) EncryptForUser(plaintext string, userID interface{}) (string, error) {
	aes := New()
	userKey := ukd.DeriveUserKey(userID)
	return aes.EncryptString(plaintext, userKey)
}

// DecryptForUser decrypts data for a specific user using a derived key
func (ukd *UserKeyDeriver) DecryptForUser(ciphertextHex string, userID interface{}) (string, error) {
	aes := New()
	userKey := ukd.DeriveUserKey(userID)
	return aes.DecryptString(ciphertextHex, userKey)
}

// ECBEncrypter implements ECB mode encryption
type ecbEncrypter struct {
	b cipher.Block
}

// NewECBEncrypter creates a new ECB mode encrypter
func NewECBEncrypter(b cipher.Block) cipher.BlockMode {
	return &ecbEncrypter{b}
}

func (x *ecbEncrypter) BlockSize() int { return x.b.BlockSize() }

func (x *ecbEncrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.BlockSize() != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	for len(src) > 0 {
		x.b.Encrypt(dst, src[:x.BlockSize()])
		src = src[x.BlockSize():]
		dst = dst[x.BlockSize():]
	}
}

// ECBDecrypter implements ECB mode decryption
type ecbDecrypter struct {
	b cipher.Block
}

// NewECBDecrypter creates a new ECB mode decrypter
func NewECBDecrypter(b cipher.Block) cipher.BlockMode {
	return &ecbDecrypter{b}
}

func (x *ecbDecrypter) BlockSize() int { return x.b.BlockSize() }

func (x *ecbDecrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.BlockSize() != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	for len(src) > 0 {
		x.b.Decrypt(dst, src[:x.BlockSize()])
		src = src[x.BlockSize():]
		dst = dst[x.BlockSize():]
	}
}
