package main

import (
	"fmt"
	"log"

	mysql_aes "github.com/ace3/mysql-aes"
)

func main() {
	fmt.Println("🔐 MySQL-Compatible AES Encryption Library Demo")
	fmt.Println("===============================================")

	// Basic encryption demo
	fmt.Println("\n1. Basic Encryption/Decryption:")
	aes := mysql_aes.New()

	data := "Confidential business data"
	key := "my-secret-key-2024"

	encrypted, err := aes.EncryptString(data, key)
	if err != nil {
		log.Fatal(err)
	}

	decrypted, err := aes.DecryptString(encrypted, key)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("   Original: %s\n", data)
	fmt.Printf("   Encrypted: %s\n", encrypted)
	fmt.Printf("   Decrypted: %s\n", decrypted)
	fmt.Printf("   ✅ Success: %v\n", data == decrypted)

	// User-specific encryption demo
	fmt.Println("\n2. User-Specific Encryption:")
	deriver := mysql_aes.NewUserKeyDeriver("base_key_2024", "app_salt")

	users := []interface{}{12345, "tenant_abc", 67890}
	userData := "sensitive user information"

	for _, userID := range users {
		encrypted, err := deriver.EncryptForUser(userData, userID)
		if err != nil {
			log.Printf("   ❌ Failed for user %v: %v", userID, err)
			continue
		}

		decrypted, err := deriver.DecryptForUser(encrypted, userID)
		if err != nil {
			log.Printf("   ❌ Decryption failed for user %v: %v", userID, err)
			continue
		}

		fmt.Printf("   User %v: %s -> %s\n", userID, encrypted[:20]+"...",
			map[bool]string{true: "✅", false: "❌"}[decrypted == userData])
	}

	// MySQL compatibility demo
	fmt.Println("\n3. MySQL Compatibility:")
	mysqlKey := "mysql_test_key"
	mysqlData := "test data for mysql"

	encrypted, _ = aes.EncryptString(mysqlData, mysqlKey)
	fmt.Printf("   Go encrypted: %s\n", encrypted)
	fmt.Printf("   MySQL decrypt command:\n")
	fmt.Printf("   SELECT AES_DECRYPT(UNHEX('%s'), '%s');\n", encrypted, mysqlKey)

	// Performance demo
	fmt.Println("\n4. Performance Test (1000 operations):")
	testData := "Performance test data for encryption benchmarking"
	testKey := "performance_key"

	// Measure encryption performance
	fmt.Print("   Encrypting 1000 times... ")
	for i := 0; i < 1000; i++ {
		_, err := aes.EncryptString(testData, testKey)
		if err != nil {
			log.Fatal(err)
		}
	}
	fmt.Println("✅ Done")

	// Measure decryption performance
	encrypted, _ = aes.EncryptString(testData, testKey)
	fmt.Print("   Decrypting 1000 times... ")
	for i := 0; i < 1000; i++ {
		_, err := aes.DecryptString(encrypted, testKey)
		if err != nil {
			log.Fatal(err)
		}
	}
	fmt.Println("✅ Done")

	fmt.Println("\n🎉 Demo completed successfully!")
	fmt.Println("\nNext steps:")
	fmt.Println("- Run 'go test -v' to see all tests")
	fmt.Println("- Run 'go test -bench=.' to see benchmarks")
	fmt.Println("- Check examples/ directory for more use cases")
	fmt.Println("- Read README.md for complete documentation")
}
