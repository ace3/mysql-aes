package main

import (
	"fmt"
	"log"

	"github.com/ace3/mysql-aes"
)

func main() {
	// Create a user key deriver with base configuration
	baseKey := "S4ty7H3mhy9sdaP54TRVne6ABDSafKqZ"
	masterSalt := "application_salt"
	deriver := mysql_aes.NewUserKeyDeriver(baseKey, masterSalt)

	// Example 1: E-commerce - Customer data encryption
	fmt.Println("=== E-commerce Customer Data ===")
	customerID := uint(12345)
	
	// Encrypt various customer data
	customerData := map[string]string{
		"email":           "customer@example.com",
		"phone":           "+1-555-0123",
		"shipping_address": "123 Main St, City, State 12345",
		"payment_method":   "card_token_abc123",
	}

	encryptedData := make(map[string]string)
	for field, value := range customerData {
		encrypted, err := deriver.EncryptForUser(value, customerID)
		if err != nil {
			log.Printf("Failed to encrypt %s: %v", field, err)
			continue
		}
		encryptedData[field] = encrypted
		fmt.Printf("Encrypted %s: %s\n", field, encrypted[:32]+"...")
	}

	// Decrypt and verify
	fmt.Println("\nDecrypted customer data:")
	for field, encrypted := range encryptedData {
		decrypted, err := deriver.DecryptForUser(encrypted, customerID)
		if err != nil {
			log.Printf("Failed to decrypt %s: %v", field, err)
			continue
		}
		fmt.Printf("%s: %s\n", field, decrypted)
	}

	// Example 2: Multi-tenant application
	fmt.Println("\n=== Multi-tenant Application ===")
	tenants := []struct {
		id   string
		data string
	}{
		{"tenant_001", "Confidential business data for tenant 1"},
		{"tenant_002", "Sensitive information for tenant 2"},
		{"tenant_003", "Private data for tenant 3"},
	}

	fmt.Println("Encrypting data for different tenants:")
	tenantData := make(map[string]string)
	for _, tenant := range tenants {
		encrypted, err := deriver.EncryptForUser(tenant.data, tenant.id)
		if err != nil {
			log.Printf("Failed to encrypt for tenant %s: %v", tenant.id, err)
			continue
		}
		tenantData[tenant.id] = encrypted
		fmt.Printf("Tenant %s: encrypted successfully\n", tenant.id)
	}

	// Verify tenant isolation
	fmt.Println("\nVerifying tenant data isolation:")
	for tenantID, encrypted := range tenantData {
		// Try to decrypt with correct tenant ID
		decrypted, err := deriver.DecryptForUser(encrypted, tenantID)
		if err != nil {
			log.Printf("Failed to decrypt for correct tenant %s: %v", tenantID, err)
			continue
		}
		fmt.Printf("✓ Tenant %s: data decrypted successfully\n", tenantID)

		// Try to decrypt with wrong tenant ID
		wrongTenantID := tenantID + "_wrong"
		wrongDecrypted, err := deriver.DecryptForUser(encrypted, wrongTenantID)
		if err != nil || wrongDecrypted == decrypted {
			fmt.Printf("✓ Tenant %s: data properly isolated from %s\n", tenantID, wrongTenantID)
		} else {
			fmt.Printf("✗ Tenant %s: data isolation failed!\n", tenantID)
		}
	}

	// Example 3: Session data encryption
	fmt.Println("\n=== Session Data Encryption ===")
	sessionIDs := []int{1001, 1002, 1003}
	sessionData := "user_preferences={theme:dark,lang:en,notifications:true}"

	fmt.Println("Encrypting session data:")
	sessions := make(map[int]string)
	for _, sessionID := range sessionIDs {
		encrypted, err := deriver.EncryptForUser(sessionData, sessionID)
		if err != nil {
			log.Printf("Failed to encrypt session %d: %v", sessionID, err)
			continue
		}
		sessions[sessionID] = encrypted
		fmt.Printf("Session %d: %s\n", sessionID, encrypted[:40]+"...")
	}

	// Example 4: Configuration encryption
	fmt.Println("\n=== Application Configuration ===")
	configs := map[string]string{
		"database_url":    "postgresql://user:pass@localhost:5432/db",
		"api_key":         "sk_live_abcdef123456789",
		"webhook_secret":  "whsec_xyz789abc123",
		"encryption_key":  "app_secret_key_2024",
	}

	appID := "myapp_v1"
	fmt.Printf("Encrypting configuration for app: %s\n", appID)
	
	encryptedConfigs := make(map[string]string)
	for key, value := range configs {
		encrypted, err := deriver.EncryptForUser(value, appID)
		if err != nil {
			log.Printf("Failed to encrypt config %s: %v", key, err)
			continue
		}
		encryptedConfigs[key] = encrypted
		fmt.Printf("Config %s: encrypted\n", key)
	}

	// Show derived keys for different entities
	fmt.Println("\n=== Derived Keys ===")
	entities := []interface{}{
		uint(12345),
		"tenant_001",
		1001,
		"myapp_v1",
	}

	for _, entity := range entities {
		derivedKey := deriver.DeriveUserKey(entity)
		fmt.Printf("Entity %v -> Key: %s\n", entity, derivedKey[:50]+"...")
	}
}
