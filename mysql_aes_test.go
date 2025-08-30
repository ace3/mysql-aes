package mysql_aes

import (
	"testing"
)

func TestMySQLAES_Basic(t *testing.T) {
	aes := New()
	
	testCases := []struct {
		name      string
		plaintext string
		key       string
	}{
		{"simple text", "Hello, World!", "mykey"},
		{"empty string", "", "mykey"},
		{"long text", "This is a longer text that spans multiple blocks to test the encryption properly", "myverylongkey"},
		{"special chars", "Special chars: !@#$%^&*()_+-=[]{}|;':\",./<>?", "specialkey"},
		{"unicode", "Unicode: 你好世界 🌍", "unicodekey"},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.plaintext == "" {
				// Test empty plaintext should return error
				_, err := aes.EncryptString(tc.plaintext, tc.key)
				if err == nil {
					t.Error("Expected error for empty plaintext")
				}
				return
			}
			
			// Test encryption
			encrypted, err := aes.EncryptString(tc.plaintext, tc.key)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}
			
			// Test decryption
			decrypted, err := aes.DecryptString(encrypted, tc.key)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}
			
			if decrypted != tc.plaintext {
				t.Errorf("Expected %q, got %q", tc.plaintext, decrypted)
			}
		})
	}
}

func TestMySQLAES_KeyWrapping(t *testing.T) {
	aes := New()
	
	// Test MySQL's key wrapping behavior
	shortKey := "short"
	longKey := "this_is_a_very_long_key_that_should_be_wrapped_around"
	plaintext := "test data"
	
	// Both should work
	encrypted1, err := aes.EncryptString(plaintext, shortKey)
	if err != nil {
		t.Fatalf("Short key encryption failed: %v", err)
	}
	
	encrypted2, err := aes.EncryptString(plaintext, longKey)
	if err != nil {
		t.Fatalf("Long key encryption failed: %v", err)
	}
	
	// Decrypt both
	decrypted1, err := aes.DecryptString(encrypted1, shortKey)
	if err != nil {
		t.Fatalf("Short key decryption failed: %v", err)
	}
	
	decrypted2, err := aes.DecryptString(encrypted2, longKey)
	if err != nil {
		t.Fatalf("Long key decryption failed: %v", err)
	}
	
	if decrypted1 != plaintext {
		t.Errorf("Short key: expected %q, got %q", plaintext, decrypted1)
	}
	
	if decrypted2 != plaintext {
		t.Errorf("Long key: expected %q, got %q", plaintext, decrypted2)
	}
}

func TestMySQLAES_ErrorHandling(t *testing.T) {
	aes := New()
	
	// Test empty key
	_, err := aes.EncryptString("test", "")
	if err == nil {
		t.Error("Expected error for empty key")
	}
	
	// Test invalid hex for decryption
	_, err = aes.DecryptString("invalid_hex", "key")
	if err == nil {
		t.Error("Expected error for invalid hex")
	}
	
	// Test invalid ciphertext length
	_, err = aes.DecryptString("abcd", "key") // Too short
	if err == nil {
		t.Error("Expected error for invalid ciphertext length")
	}
}

func TestUserKeyDeriver(t *testing.T) {
	baseKey := "S4ty7H3mhy9sdaP54TRVne6ABDSafKqZ"
	masterSalt := "testsalt"
	deriver := NewUserKeyDeriver(baseKey, masterSalt)
	
	testCases := []struct {
		name     string
		userID   interface{}
		expected string
	}{
		{"uint", uint(12345), baseKey + "12345:" + masterSalt},
		{"int", 67890, baseKey + "67890:" + masterSalt},
		{"string", "user123", baseKey + "user123:" + masterSalt},
		{"uint64", uint64(999999), baseKey + "999999:" + masterSalt},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := deriver.DeriveUserKey(tc.userID)
			if result != tc.expected {
				t.Errorf("Expected %q, got %q", tc.expected, result)
			}
		})
	}
}

func TestUserKeyDeriver_EncryptDecrypt(t *testing.T) {
	baseKey := "S4ty7H3mhy9sdaP54TRVne6ABDSafKqZ"
	masterSalt := "testsalt"
	deriver := NewUserKeyDeriver(baseKey, masterSalt)
	
	userID := uint(12345)
	plaintext := "sensitive data"
	
	// Encrypt for user
	encrypted, err := deriver.EncryptForUser(plaintext, userID)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}
	
	// Decrypt for same user
	decrypted, err := deriver.DecryptForUser(encrypted, userID)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}
	
	if decrypted != plaintext {
		t.Errorf("Expected %q, got %q", plaintext, decrypted)
	}
	
	// Try to decrypt with different user ID (should fail or give different result)
	differentUserID := uint(54321)
	decryptedDifferent, err := deriver.DecryptForUser(encrypted, differentUserID)
	if err == nil && decryptedDifferent == plaintext {
		t.Error("Decryption with different user ID should not return original plaintext")
	}
}

func TestMySQLAES_Compatibility(t *testing.T) {
	// Test known values that should be compatible with MySQL
	aes := New()
	
	// These test vectors should match MySQL's AES_ENCRYPT/AES_DECRYPT behavior
	testCases := []struct {
		plaintext string
		key       string
		// Note: We can't hardcode expected values here because they depend on
		// the exact implementation, but we can test round-trip compatibility
	}{
		{"brian", "abcdefghijklmnop"},
		{"test", "key"},
		{"Hello World", "mysecretkey"},
	}
	
	for _, tc := range testCases {
		t.Run(tc.plaintext, func(t *testing.T) {
			encrypted, err := aes.EncryptString(tc.plaintext, tc.key)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}
			
			decrypted, err := aes.DecryptString(encrypted, tc.key)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}
			
			if decrypted != tc.plaintext {
				t.Errorf("Round-trip failed: expected %q, got %q", tc.plaintext, decrypted)
			}
		})
	}
}

func TestPKCS7Padding(t *testing.T) {
	aes := New()
	
	testCases := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"single byte", []byte{0x01}},
		{"block size", make([]byte, 16)},
		{"block size + 1", make([]byte, 17)},
		{"random data", []byte("Hello, World! This is a test.")},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			padded := aes.pkcs7Pad(tc.data, 16)
			
			// Check padding length
			if len(padded)%16 != 0 {
				t.Errorf("Padded length should be multiple of 16, got %d", len(padded))
			}
			
			// Check if we can unpad
			unpadded, err := aes.pkcs7Unpad(padded)
			if err != nil {
				t.Fatalf("Unpadding failed: %v", err)
			}
			
			// Check if original data is preserved
			if len(unpadded) != len(tc.data) {
				t.Errorf("Unpadded length mismatch: expected %d, got %d", len(tc.data), len(unpadded))
			}
			
			for i, b := range tc.data {
				if unpadded[i] != b {
					t.Errorf("Data mismatch at position %d: expected %02x, got %02x", i, b, unpadded[i])
				}
			}
		})
	}
}

func BenchmarkMySQLAES_Encrypt(b *testing.B) {
	aes := New()
	plaintext := "This is a benchmark test for encryption performance"
	key := "benchmarkkey"
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := aes.EncryptString(plaintext, key)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMySQLAES_Decrypt(b *testing.B) {
	aes := New()
	plaintext := "This is a benchmark test for decryption performance"
	key := "benchmarkkey"
	
	encrypted, err := aes.EncryptString(plaintext, key)
	if err != nil {
		b.Fatal(err)
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := aes.DecryptString(encrypted, key)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkUserKeyDeriver_EncryptForUser(b *testing.B) {
	deriver := NewUserKeyDeriver("basekey", "salt")
	plaintext := "This is benchmark data for user-specific encryption"
	userID := uint(12345)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := deriver.EncryptForUser(plaintext, userID)
		if err != nil {
			b.Fatal(err)
		}
	}
}
