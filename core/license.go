package core

import (
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/scripttoken/script/common"
	"github.com/scripttoken/script/crypto"

	"github.com/scripttoken/script/crypto/sha3"
	"github.com/spf13/viper"
)

type LicenseReadFile struct {
	Issuer    common.Address `json:"issuer"`    // Issuer's address
	Licensee  common.Address `json:"licensee"`  // Licensee's address
	From      string         `json:"from"`      // Start time (unix timestamp)
	To        string         `json:"to"`        // End time (unix timestamp)
	Items     []string       `json:"items"`     // Items covered by the license
	Signature string         `json:"signature"` // Base64-encoded signature
}

type License struct {
	Issuer    common.Address `json:"issuer"`    // Issuer's address
	Licensee  common.Address `json:"licensee"`  // Licensee's address
	From      uint64         `json:"from"`      // Start time (unix timestamp)
	To        uint64         `json:"to"`        // End time (unix timestamp)
	Items     []string       `json:"items"`     // Items covered by the license
	Signature string         `json:"signature"` // Base64-encoded signature
}

// Package-level variable to store the license map
var licenseMap = make(map[common.Address]License)
var licenseFile = viper.GetString(common.CfgLicenseDir) + "/license.json"

// Cache for pre-verified licenses
var verifiedLicenseCache = make(map[common.Address]bool)

// Set license filename globally
func SetLicenseFile(filename string) {
	licenseFile = filename
}

// Read license file
func ReadFile(filename string) (map[common.Address]License, error) {
	fmt.Printf("LICENSE_READ License file path: %v\n", viper.GetString(common.CfgLicenseDir))
	if filename == "" {
		filename = licenseFile
	}

	fmt.Printf("LICENSE_READ License file path: %v\n", filename)
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("LICENSE_READ Failed to open file: %v at %v", err, licenseFile)
	}
	defer file.Close()

	bytes, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("LICENSE_READ Failed to read file: %v", err)
	}

	var licenses []LicenseReadFile
	err = json.Unmarshal(bytes, &licenses)
	if err != nil {
		return nil, fmt.Errorf("LICENSE_READ Failed to unmarshal JSON: %v", err)
	}

	licenseMap = make(map[common.Address]License)        // clear previous map
	verifiedLicenseCache = make(map[common.Address]bool) // clear previous cache

	for _, licenseRF := range licenses {
		/*fromTime, err := time.Parse(time.RFC3339, licenseRF.From)
		if err != nil {
			return nil, fmt.Errorf("Failed to parse 'From' field: %v", err)
		}
		from := uint64(fromTime.Unix())

		toTime, err := time.Parse(time.RFC3339, licenseRF.To)
		if err != nil {
			return nil, fmt.Errorf("Failed to parse 'To' field: %v", err)
		}
		to := uint64(toTime.Unix())*/
		from, err := strconv.ParseInt(licenseRF.From, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("LICENSE_READ Failed to parse 'From' field: %v", err)
		}

		to, err := strconv.ParseInt(licenseRF.To, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("LICENSE_READ Failed to parse 'To' field: %v", err)
		}

		license := License{
			Issuer:    licenseRF.Issuer,
			Licensee:  licenseRF.Licensee,
			From:      uint64(from),
			To:        uint64(to),
			Items:     licenseRF.Items,
			Signature: licenseRF.Signature,
		}

		if err = ValidateIncomingLicense(license); err != nil {
			return nil, fmt.Errorf("LICENSE_READ Failed to validate license for licensee %v: %v", license.Licensee.Hex(), err)
		}

		licenseMap[license.Licensee] = license
	}

	return licenseMap, nil
}

type ECDSASignature struct {
	R, S *big.Int
}

func ConvertDERToECDSA(derSig []byte, recKey int) ([]byte, error) {
	var sig ECDSASignature
	_, err := asn1.Unmarshal(derSig, &sig)
	if err != nil {
		return nil, errors.New("failed to parse DER signature")
	}

	// Ensure r and s are 32 bytes each
	rBytes := sig.R.Bytes()
	sBytes := sig.S.Bytes()

	r := make([]byte, 32)
	s := make([]byte, 32)
	copy(r[32-len(rBytes):], rBytes)
	copy(s[32-len(sBytes):], sBytes)

	v := byte(recKey)
	return append(append(r, s...), v), nil
}

// ConvertStringToSignature converts a base64-encoded string to a Signature object.
func ConvertStringToSignature(signatureStr string, recKey int) (*crypto.Signature, error) {
	decodedSig, err := base64.StdEncoding.DecodeString(signatureStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 signature: %v", err)
	}

	fmt.Println("LICENSE_VALIDATE decoded signature ", decodedSig)
	ecdsaSig, err := ConvertDERToECDSA(decodedSig, recKey)
	if err != nil {
		return nil, fmt.Errorf("failed to convert DER to raw signature: %v", err)
	}
	fmt.Println("LICENSE_VALIDATE raw signature (converted):", ecdsaSig)

	return crypto.NewSignature(ecdsaSig), nil
}

func WriteLicenseFile(license License, filename string) error {
	err := ValidateIncomingLicense(license)
	if err != nil {
		return fmt.Errorf("License validation failed: %v", err)
	}

	if filename == "" {
		filename = licenseFile
	}

	file, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return fmt.Errorf("Failed to open license file: %v", err)
	}
	defer file.Close()

	licenseJSON, err := json.Marshal(license)
	if err != nil {
		return fmt.Errorf("Failed to marshal license to JSON: %v", err)
	}

	_, err = file.Write(licenseJSON)
	if err != nil {
		return fmt.Errorf("Failed to write license to file: %v", err)
	}

	_, err = file.WriteString("\n")
	if err != nil {
		return fmt.Errorf("Failed to write newline to file: %v", err)
	}
	return nil
}

func ValidateIncomingLicense(license License) error {
	fmt.Println("LICENSE_VALIDATION Starting license validation")
	currentTime := uint64(time.Now().Unix())

	// Validate the license period
	if license.From > currentTime || license.To < currentTime {
		return fmt.Errorf("LICENSE_VALIDATE_I Current time is outside the valid license period")
	}

	// Validate the license items
	if !isLicenseForValidatorNode(license.Items) && !isLicenseForLightningNode(license.Items) {
		return fmt.Errorf("LICENSE_VALIDATE_I License items are invalid or empty")
	}

	// Try the signature verification with two recovery keys (0 and 1)
	var validationError error
	dataToVerify := concatenateLicenseData(license)
	for v := 0; v <= 1; v++ {
		// Convert string signature to the object
		signature, err := ConvertStringToSignature(license.Signature, v)
		if err != nil {
			fmt.Println("LICENSE_VALIDATE_I Failed to convert string to signature (v=%d): %v\n", v, err)
			validationError = fmt.Errorf("failed to convert string to signature (v=%d): %w", v, err)
			continue
		}

		// Verify license signature
		isValid := signature.VerifySignature(dataToVerify, license.Issuer)
		fmt.Printf("LICENSE_VALIDATION_II isValid: %v (v=%d)\n", isValid, v)
		if isValid {
			fmt.Println("LICENSE_VALIDATE_I License is valid.")
			return nil
		}
	}

	if validationError != nil {
		return fmt.Errorf("LICENSE_VALIDATE_I Invalid license: %w", validationError)
	}
	return fmt.Errorf("LICENSE_VALIDATE_I Invalid license: no valid signature found")
}

func keccak256(data ...[]byte) []byte {
	d := sha3.NewKeccak256()
	for _, b := range data {
		d.Write(b)
	}
	return d.Sum(nil)
}

// validate license for a public key
func ValidateLicense(licensee common.Address) error {
	// Check cache first
	if _, exists := verifiedLicenseCache[licensee]; exists {
		return nil // License exists in the cache
	}

	license, exists := licenseMap[licensee]
	if !exists {
		return fmt.Errorf("LICENSE_VALIDATE No license found for the given licensee public key: %v", licensee)
	}

	currentTime := uint64(time.Now().Unix())
	if license.From > currentTime || license.To < currentTime {
		verifiedLicenseCache[licensee] = false
		return fmt.Errorf("LICENSE_VALIDATE Current time is outside the valid license period")
	}

	// Try the signature verification with two recovery keys (0 and 1)
	var validationError error
	dataToVerify := concatenateLicenseData(license)
	for v := 0; v <= 1; v++ {
		// Convert string signature to the object
		signature, err := ConvertStringToSignature(license.Signature, v)
		if err != nil {
			fmt.Println("LICENSE_VALIDATE_I Failed to convert string to signature (v=%d): %v\n", v, err)
			validationError = fmt.Errorf("LICENSE_VALIDATE Failed to convert string to signature: %v", err)
			continue
		}

		// Verify license signature
		isValid := signature.VerifySignature(dataToVerify, license.Issuer)
		fmt.Printf("LICENSE_VALIDATION_II isValid: %v (v=%d)\n", isValid, v)
		if isValid {
			// Cache the verified status
			verifiedLicenseCache[licensee] = true
			return nil
		}
	}

	if validationError != nil {
		verifiedLicenseCache[licensee] = false
		return fmt.Errorf("LICENSE_VALIDATE Invalid license signature:%v, %v, %x", license.Issuer.Hex(), dataToVerify, keccak256(dataToVerify))
	}
	return fmt.Errorf("LICENSE_VALIDATE_I Invalid license: no valid signature found")
}

func isLicenseForValidatorNode(items []string) bool {
	for _, item := range items {
		if item == "VN" {
			return true
		}
	}
	return false
}

func isLicenseForLightningNode(items []string) bool {
	for _, item := range items {
		if item == "LN" || item == "LN-L" {
			return true
		}
	}
	return false
}

func concatenateLicenseData(license License) []byte {
	issuer := strings.ToUpper(license.Issuer.Hex())
	licensee := strings.ToUpper(license.Licensee.Hex())
	from := fmt.Sprintf("%d", license.From)
	to := fmt.Sprintf("%d", license.To)

	// Concatenate license iterms in a single string
	items := ""
	for _, item := range license.Items {
		items += item
	}

	dataToVerify := issuer + licensee + from + to + items
	return common.Bytes(dataToVerify)
}

// periodically check and update the cache
func startCacheUpdater(interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			updateCache()
		}
	}()
}

func updateCache() {
	currentTime := uint64(time.Now().Unix())
	for licensee, license := range licenseMap {
		if license.From > currentTime || license.To < currentTime {
			delete(verifiedLicenseCache, licensee)
		}
	}
}

func init() {
	startCacheUpdater(1 * time.Hour)
}
