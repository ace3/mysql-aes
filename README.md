# MySQL-Compatible AES Encryption Library for Go

A comprehensive Go library that provides MySQL-compatible AES encryption and decryption functionality. This library ensures that data encrypted in Go can be decrypted using MySQL's `AES_DECRYPT` function and vice versa, maintaining full compatibility between application-level and database-level operations.

## Features

- **MySQL Compatibility**: Full compatibility with MySQL's `AES_ENCRYPT` and `AES_DECRYPT` functions
- **User-Specific Key Derivation**: Built-in support for user-specific encryption with configurable key derivation
- **Generic Data Encryption**: Suitable for encrypting any type of sensitive data, not limited to PII
- **Easy Integration**: Simple API for common encryption/decryption operations
- **Performance Optimized**: Efficient implementation with minimal overhead
- **Well Tested**: Comprehensive test suite with benchmarks
- **Proper Error Handling**: Detailed error messages for debugging

## Installation

```bash
go get github.com/ace3/mysql-aes
```

## Quick Start

### Basic AES Encryption/Decryption

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/ace3/mysql-aes"
)

func main() {
    // Create a new MySQLAES instance
    aes := mysql_aes.New()
    
    // Encrypt a string
    plaintext := "Hello, World!"
    key := "myencryptionkey"
    
    encrypted, err := aes.EncryptString(plaintext, key)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Encrypted: %s\n", encrypted)
    
    // Decrypt the string
    decrypted, err := aes.DecryptString(encrypted, key)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Decrypted: %s\n", decrypted)
}
```

### User-Specific Data Encryption

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/ace3/mysql-aes"
)

func main() {
    // Create a user key deriver with base configuration
    baseKey := "S4ty7H3mhy9sdaP54TRVne6ABDSafKqZ"
    masterSalt := "mysalt"
    deriver := mysql_aes.NewUserKeyDeriver(baseKey, masterSalt)
    
    // Encrypt sensitive data for user 12345
    userID := uint(12345)
    sensitiveData := "credit_card_number_1234567890"
    
    encryptedData, err := deriver.EncryptForUser(sensitiveData, userID)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Encrypted data: %s\n", encryptedData)
    
    // Decrypt the data
    decryptedData, err := deriver.DecryptForUser(encryptedData, userID)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Decrypted data: %s\n", decryptedData)
    
    // Show the derived key for this user
    userKey := deriver.DeriveUserKey(userID)
    fmt.Printf("User key: %s\n", userKey)
}
```

### Working with Binary Data

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/ace3/mysql-aes"
)

func main() {
    aes := mysql_aes.New()
    
    // Encrypt binary data
    data := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
    key := []byte("mysecretkey")
    
    encrypted, err := aes.Encrypt(data, key)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Encrypted bytes: %x\n", encrypted)
    
    // Decrypt binary data
    decrypted, err := aes.Decrypt(encrypted, key)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Decrypted bytes: %x\n", decrypted)
}
```

## API Reference

### MySQLAES

#### `New() *MySQLAES`
Creates a new MySQLAES instance.

#### `Encrypt(plaintext, key []byte) ([]byte, error)`
Encrypts plaintext using AES-ECB mode, compatible with MySQL's `AES_ENCRYPT` function.

#### `Decrypt(ciphertext, key []byte) ([]byte, error)`
Decrypts ciphertext using AES-ECB mode, compatible with MySQL's `AES_DECRYPT` function.

#### `EncryptString(plaintext, key string) (string, error)`
Encrypts a string and returns the result as a hex string.

#### `DecryptString(ciphertextHex, key string) (string, error)`
Decrypts a hex string and returns the result as a string.

### UserKeyDeriver

#### `NewUserKeyDeriver(baseKey, masterSalt string) *UserKeyDeriver`
Creates a new UserKeyDeriver with base configuration.

#### `DeriveUserKey(userID interface{}) string`
Derives a user-specific encryption key using the formula: `baseKey + userID + ":" + masterSalt`

Supports various user ID types:
- `uint`, `uint64`
- `int`, `int64`
- `string`
- Any other type (converted to string)

#### `EncryptForUser(plaintext string, userID interface{}) (string, error)`
Encrypts data for a specific user using a derived key.

#### `DecryptForUser(ciphertextHex string, userID interface{}) (string, error)`
Decrypts data for a specific user using a derived key.

## MySQL Integration

This library is fully compatible with MySQL's AES functions. You can encrypt data in Go and decrypt it in MySQL, or vice versa.

### MySQL Examples

```sql
-- Encrypt in MySQL
SELECT HEX(AES_ENCRYPT('Hello, World!', 'myencryptionkey')) as encrypted;

-- Decrypt in MySQL (using hex string from Go)
SELECT AES_DECRYPT(UNHEX('your_hex_string_here'), 'myencryptionkey') as decrypted;
```

### Go to MySQL Workflow

```go
// Encrypt in Go
aes := mysql_aes.New()
encrypted, _ := aes.EncryptString("sensitive data", "mykey")

// Store encrypted (hex string) in database
// Later, decrypt in MySQL:
// SELECT AES_DECRYPT(UNHEX(encrypted_column), 'mykey') FROM table;
```

### MySQL to Go Workflow

```sql
-- Encrypt in MySQL and store as hex
INSERT INTO table (encrypted_column) VALUES (HEX(AES_ENCRYPT('data', 'mykey')));
```

```go
// Retrieve and decrypt in Go
aes := mysql_aes.New()
decrypted, _ := aes.DecryptString(encryptedFromDB, "mykey")
```

## Use Cases

### 1. E-commerce Platform
```go
// Encrypt customer payment information
deriver := mysql_aes.NewUserKeyDeriver("payment_base_key", "secure_salt")
customerID := 12345

// Encrypt credit card number
encryptedCC, _ := deriver.EncryptForUser("4111111111111111", customerID)

// Store in database, decrypt when needed
decryptedCC, _ := deriver.DecryptForUser(encryptedCC, customerID)
```

### 2. Healthcare System
```go
// Encrypt patient medical records
deriver := mysql_aes.NewUserKeyDeriver("medical_base_key", "hipaa_salt")
patientID := "P123456"

// Encrypt medical data
encryptedRecord, _ := deriver.EncryptForUser("Patient diagnosis: ...", patientID)
```

### 3. Financial Services
```go
// Encrypt account numbers and transaction data
deriver := mysql_aes.NewUserKeyDeriver("financial_base_key", "compliance_salt")
accountID := 987654321

// Encrypt account details
encryptedAccount, _ := deriver.EncryptForUser("ACC-123-456-789", accountID)
```

### 4. Generic Data Protection
```go
// Encrypt any sensitive configuration or user data
aes := mysql_aes.New()

// API keys
encryptedAPIKey, _ := aes.EncryptString("sk_live_abc123...", "config_key")

// User preferences
encryptedPrefs, _ := aes.EncryptString(`{"theme":"dark","lang":"en"}`, "user_prefs_key")
```

## Security Considerations

1. **Key Management**: Store encryption keys securely, separate from encrypted data
2. **Key Rotation**: Implement key rotation policies for long-term security
3. **Salt Uniqueness**: Use unique salts for different applications/environments
4. **Access Control**: Limit access to encryption keys and sensitive operations
5. **Audit Logging**: Log encryption/decryption operations for compliance

## Performance

The library is optimized for performance with minimal overhead:

```bash
# Run benchmarks
go test -bench=.

# Example results on modern hardware:
BenchmarkMySQLAES_Encrypt-8         500000    3000 ns/op
BenchmarkMySQLAES_Decrypt-8         500000    3200 ns/op
BenchmarkUserKeyDeriver_EncryptForUser-8  300000    4000 ns/op
```

## Testing

Run the comprehensive test suite:

```bash
# Run all tests
go test -v

# Run tests with coverage
go test -v -cover

# Run benchmarks
go test -bench=.
```

## Migration from Existing Systems

### From crypticmysql
```go
// Old crypticmysql usage:
// encrypted := crypticmysql.AESEncrypt([]byte("data"), []byte("key"))
// decrypted := crypticmysql.AESDecrypt(encrypted, []byte("key"))

// New mysql-aes usage:
aes := mysql_aes.New()
encrypted, _ := aes.Encrypt([]byte("data"), []byte("key"))
decrypted, _ := aes.Decrypt(encrypted, []byte("key"))
```

### From Other AES Libraries
The library provides MySQL-compatible encryption, so you may need to re-encrypt existing data if migrating from other AES implementations that use different modes (CBC, GCM, etc.).

## Configuration

### Environment Variables
```bash
export MYSQL_AES_BASE_KEY="your_base_key_here"
export MYSQL_AES_MASTER_SALT="your_master_salt_here"
```

### Using with Configuration Libraries
```go
// With viper
baseKey := viper.GetString("mysql_aes.base_key")
masterSalt := viper.GetString("mysql_aes.master_salt")
deriver := mysql_aes.NewUserKeyDeriver(baseKey, masterSalt)

// With environment variables
baseKey := os.Getenv("MYSQL_AES_BASE_KEY")
masterSalt := os.Getenv("MYSQL_AES_MASTER_SALT")
deriver := mysql_aes.NewUserKeyDeriver(baseKey, masterSalt)
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup
```bash
git clone https://github.com/ace3/mysql-aes.git
cd mysql-aes
go mod tidy
go test -v
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- **Issues**: [GitHub Issues](https://github.com/ace3/mysql-aes/issues)
- **Documentation**: This README and inline code documentation
- **Examples**: See the `examples/` directory for more usage examples

## Acknowledgments

- Based on [bketelsen/crypticmysql](https://github.com/bketelsen/crypticmysql) for MySQL compatibility
- Inspired by the need for seamless Go-MySQL encryption interoperability
- Thanks to the Go crypto community for excellent cryptographic primitives
