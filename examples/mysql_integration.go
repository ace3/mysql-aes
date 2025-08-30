package main

import (
	"fmt"
	"log"

	"github.com/ace3/mysql-aes"
)

func main() {
	aes := mysql_aes.New()

	// Example 1: Data that will be decrypted in MySQL
	fmt.Println("=== Go Encrypt -> MySQL Decrypt ===")
	plaintext := "Sensitive data to be stored in database"
	key := "database_encryption_key"

	// Encrypt in Go
	encrypted, err := aes.EncryptString(plaintext, key)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Original data: %s\n", plaintext)
	fmt.Printf("Encrypted (hex): %s\n", encrypted)
	fmt.Printf("MySQL query to decrypt:\n")
	fmt.Printf("SELECT AES_DECRYPT(UNHEX('%s'), '%s') AS decrypted_data;\n", encrypted, key)

	// Verify by decrypting in Go
	decrypted, err := aes.DecryptString(encrypted, key)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Verification (Go decrypt): %s\n", decrypted)

	// Example 2: Simulating MySQL encryption (what you'd get from MySQL)
	fmt.Println("\n=== MySQL Encrypt -> Go Decrypt ===")
	
	// These are example hex values that would come from MySQL AES_ENCRYPT
	// In real usage, you'd get these from: SELECT HEX(AES_ENCRYPT('data', 'key'))
	mysqlEncryptedExamples := map[string]struct {
		encrypted string
		key       string
		expected  string
	}{
		"simple": {
			// This would be the result of: SELECT HEX(AES_ENCRYPT('test', 'key'))
			encrypted: "", // We'll generate this dynamically for demonstration
			key:       "key",
			expected:  "test",
		},
	}

	// Generate the encrypted values using our library (simulating MySQL)
	for name, example := range mysqlEncryptedExamples {
		// Simulate what MySQL would produce
		encrypted, err := aes.EncryptString(example.expected, example.key)
		if err != nil {
			log.Printf("Failed to encrypt %s: %v", name, err)
			continue
		}
		
		fmt.Printf("Example: %s\n", name)
		fmt.Printf("  MySQL command: SELECT HEX(AES_ENCRYPT('%s', '%s'));\n", example.expected, example.key)
		fmt.Printf("  Expected hex result: %s\n", encrypted)
		
		// Decrypt in Go
		decrypted, err := aes.DecryptString(encrypted, example.key)
		if err != nil {
			log.Printf("  Go decryption failed: %v", err)
			continue
		}
		fmt.Printf("  Go decrypted result: %s\n", decrypted)
		fmt.Printf("  Match: %v\n", decrypted == example.expected)
	}

	// Example 3: Database schema suggestions
	fmt.Println("\n=== Database Schema Suggestions ===")
	fmt.Println("-- Table with encrypted columns")
	fmt.Println("CREATE TABLE users (")
	fmt.Println("    id INT PRIMARY KEY AUTO_INCREMENT,")
	fmt.Println("    username VARCHAR(255) NOT NULL,")
	fmt.Println("    email_encrypted TEXT,          -- Store hex-encoded encrypted email")
	fmt.Println("    phone_encrypted TEXT,          -- Store hex-encoded encrypted phone")
	fmt.Println("    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
	fmt.Println(");")
	
	fmt.Println("\n-- Insert encrypted data (from Go application)")
	userEmail := "user@example.com"
	userPhone := "+1-555-0123"
	encryptionKey := "user_data_key"
	
	encryptedEmail, _ := aes.EncryptString(userEmail, encryptionKey)
	encryptedPhone, _ := aes.EncryptString(userPhone, encryptionKey)
	
	fmt.Printf("INSERT INTO users (username, email_encrypted, phone_encrypted) VALUES\n")
	fmt.Printf("('john_doe', '%s', '%s');\n", encryptedEmail, encryptedPhone)
	
	fmt.Println("\n-- Decrypt in MySQL query")
	fmt.Printf("SELECT \n")
	fmt.Printf("    username,\n")
	fmt.Printf("    AES_DECRYPT(UNHEX(email_encrypted), '%s') AS email,\n", encryptionKey)
	fmt.Printf("    AES_DECRYPT(UNHEX(phone_encrypted), '%s') AS phone\n", encryptionKey)
	fmt.Printf("FROM users WHERE username = 'john_doe';\n")

	// Example 4: Batch operations
	fmt.Println("\n=== Batch Operations ===")
	batchData := []struct {
		id   int
		data string
	}{
		{1, "First record data"},
		{2, "Second record data"},
		{3, "Third record data"},
	}

	batchKey := "batch_processing_key"
	fmt.Println("Encrypting batch data:")
	
	for _, record := range batchData {
		encrypted, err := aes.EncryptString(record.data, batchKey)
		if err != nil {
			log.Printf("Failed to encrypt record %d: %v", record.id, err)
			continue
		}
		fmt.Printf("Record %d: %s -> %s\n", record.id, record.data, encrypted[:32]+"...")
		
		// Show corresponding MySQL operations
		fmt.Printf("  MySQL INSERT: INSERT INTO records (id, encrypted_data) VALUES (%d, '%s');\n", record.id, encrypted)
		fmt.Printf("  MySQL SELECT: SELECT id, AES_DECRYPT(UNHEX(encrypted_data), '%s') FROM records WHERE id = %d;\n", batchKey, record.id)
	}

	// Example 5: Key rotation simulation
	fmt.Println("\n=== Key Rotation Example ===")
	originalKey := "old_encryption_key"
	newKey := "new_encryption_key_2024"
	testData := "Data that needs key rotation"

	// Encrypt with old key
	encryptedWithOldKey, err := aes.EncryptString(testData, originalKey)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Data encrypted with old key: %s\n", encryptedWithOldKey[:32]+"...")

	// Decrypt with old key
	decryptedData, err := aes.DecryptString(encryptedWithOldKey, originalKey)
	if err != nil {
		log.Fatal(err)
	}

	// Re-encrypt with new key
	encryptedWithNewKey, err := aes.EncryptString(decryptedData, newKey)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Data re-encrypted with new key: %s\n", encryptedWithNewKey[:32]+"...")

	// Verify with new key
	verifyDecryption, err := aes.DecryptString(encryptedWithNewKey, newKey)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Key rotation successful: %v\n", verifyDecryption == testData)

	fmt.Println("\n-- MySQL key rotation queries:")
	fmt.Printf("-- Step 1: Decrypt with old key and re-encrypt with new key\n")
	fmt.Printf("UPDATE table_name SET \n")
	fmt.Printf("    encrypted_column = HEX(AES_ENCRYPT(AES_DECRYPT(UNHEX(encrypted_column), '%s'), '%s'))\n", originalKey, newKey)
	fmt.Printf("WHERE encrypted_column IS NOT NULL;\n")
}
