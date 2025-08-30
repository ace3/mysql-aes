package main

import (
	"fmt"
	"log"

	"github.com/ace3/mysql-aes"
)

func main() {
	// Create a new MySQLAES instance
	aes := mysql_aes.New()

	// Example 1: Basic string encryption/decryption
	fmt.Println("=== Basic String Encryption ===")
	plaintext := "Hello, World!"
	key := "myencryptionkey"

	encrypted, err := aes.EncryptString(plaintext, key)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Original: %s\n", plaintext)
	fmt.Printf("Encrypted (hex): %s\n", encrypted)

	decrypted, err := aes.DecryptString(encrypted, key)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Decrypted: %s\n", decrypted)

	// Example 2: Working with binary data
	fmt.Println("\n=== Binary Data Encryption ===")
	binaryData := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0xFF, 0xFE}
	binaryKey := []byte("binarykey")

	encryptedBinary, err := aes.Encrypt(binaryData, binaryKey)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Original binary: %x\n", binaryData)
	fmt.Printf("Encrypted binary: %x\n", encryptedBinary)

	decryptedBinary, err := aes.Decrypt(encryptedBinary, binaryKey)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Decrypted binary: %x\n", decryptedBinary)

	// Example 3: Different key lengths
	fmt.Println("\n=== Different Key Lengths ===")
	testData := "Test data for different keys"
	
	keys := []string{
		"short",                                    // Short key
		"exactly16byteskey",                       // Exactly 16 bytes
		"this_is_a_very_long_key_that_exceeds_16_bytes", // Long key (will be wrapped)
	}

	for i, testKey := range keys {
		encrypted, err := aes.EncryptString(testData, testKey)
		if err != nil {
			log.Printf("Key %d failed: %v", i+1, err)
			continue
		}
		
		decrypted, err := aes.DecryptString(encrypted, testKey)
		if err != nil {
			log.Printf("Decryption for key %d failed: %v", i+1, err)
			continue
		}
		
		fmt.Printf("Key %d (%d chars): %s -> %s\n", i+1, len(testKey), testKey[:min(20, len(testKey))], 
			map[bool]string{true: "✓", false: "✗"}[decrypted == testData])
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
