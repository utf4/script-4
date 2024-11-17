package core

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/scripttoken/script/common"
	"github.com/spf13/viper"
	"github.com/scripttoken/script/crypto"
)

type License struct {
	Issuer    common.Address `json:"issuer"`    // Issuer's address
	Licensee  common.Address `json:"licensee"`  // Licensee's address
	From      uint64         `json:"from"`      // Start time (unix timestamp)
	To        uint64         `json:"to"`        // End time (unix timestamp)
	Items     []string       `json:"items"`     // Items covered by the license
	Signature string         `json:"signature"` // Base64-encoded signature
}

// package-level variable to store the license map
var licenseMap = make(map[common.Address]License)
var licenseFile = viper.GetString(common.CfgLicenseDir) + "/license.json"

// cache for pre-verified licenses
var verifiedLicenseCache = make(map[common.Address]bool)

// read license file
func ReadFile(filename string) (map[common.Address]License, error) {
	if filename == "" {
		filename = viper.GetString(common.CfgLicenseDir) + "/license.json"
	}

	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("Failed to open file: %v at %v", err, viper.GetString(common.CfgLicenseDir))
	}
	defer file.Close()

	bytes, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("Failed to read file: %v", err)
	}

	var licenses []License

	err = json.Unmarshal(bytes, &licenses)
	if err != nil {
		return nil, fmt.Errorf("Failed to unmarshal JSON: %v", err)
	}

	licenseMap = make(map[common.Address]License) // clear previous map
	verifiedLicenseCache = make(map[common.Address]bool) // clear previous cache

	for _, license := range licenses {
		licenseMap[license.Licensee] = license
	}

	return licenseMap, nil
}

// ConvertStringToSignature converts a base64-encoded string to a Signature object.
func ConvertStringToSignature(signatureStr string) (*crypto.Signature, error) {
	decodedSig, err := base64.StdEncoding.DecodeString(signatureStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 signature: %v", err)
	}

	signature := crypto.NewSignature(decodedSig)

	return signature, nil
}

func WriteLicenseFile(license License, filename string) error {
	err := ValidateIncomingLicense(license)
	if err != nil {
		return fmt.Errorf("license validation failed: %v", err)
	}

	if filename == "" {
		filename = viper.GetString(common.CfgLicenseDir) + "/license.json"
	}

	file, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return fmt.Errorf("failed to open license file: %v", err)
	}
	defer file.Close()

	licenseJSON, err := json.Marshal(license)
	if err != nil {
		return fmt.Errorf("failed to marshal license to JSON: %v", err)
	}

	_, err = file.Write(licenseJSON)
	if err != nil {
		return fmt.Errorf("failed to write license to file: %v", err)
	}

	_, err = file.WriteString("\n")
	if err != nil {
		return fmt.Errorf("failed to write newline to file: %v", err)
	}

	return nil
}

func ValidateIncomingLicense(license License) error {
	currentTime := uint64(time.Now().Unix())

	if license.From > currentTime || license.To < currentTime {
		return fmt.Errorf("current time is outside the valid license period")
	}

	if !isLicenseForValidatorNode(license.Items) {
		return fmt.Errorf("license items do not include 'VN'")
	}

	dataToSign := concatenateLicenseData(license)

	signature, err := ConvertStringToSignature(license.Signature)
	if err != nil {
		return fmt.Errorf("failed to convert string to signature: %v", err)
	}
	if !signature.Verify(dataToSign, license.Issuer) {
		return fmt.Errorf("invalid license signature")
	}

	return nil
}

// validate license for a public key
func ValidateLicense(licensee common.Address) error {
	// Check cache first
	if verified, exists := verifiedLicenseCache[licensee]; exists {
		if verified {
			return nil // License is already verified
		} else {
			return fmt.Errorf("license is not verified")
		}
	}

	license, exists := licenseMap[licensee]
	if !exists {
		return fmt.Errorf("No license found for the given licensee public key")
	}

	currentTime := uint64(time.Now().Unix())

	if license.From > currentTime || license.To < currentTime {
		verifiedLicenseCache[licensee] = false
		return fmt.Errorf("current time is outside the valid license period")
	}

	dataToValidate := concatenateLicenseData(license)

	signature, err := ConvertStringToSignature(license.Signature)
	if err != nil {
		return fmt.Errorf("failed to convert string to signature: %v", err)
	}
	if !signature.Verify(dataToValidate, license.Issuer) {
		verifiedLicenseCache[licensee] = false
		return fmt.Errorf("invalid license signature")
	}

	// cache the verified status
	verifiedLicenseCache[licensee] = true

	// valid license
	return nil
}

func isLicenseForValidatorNode(items []string) bool {
	for _, item := range items {
		if item == "VN" {
			return true
		}
	}
	return false
}

func concatenateLicenseData(license License) []byte {
	// Convert fields to byte slices or strings
	issuerBytes := []byte(license.Issuer.Hex())
	licenseeBytes := []byte(license.Licensee.Hex())
	fromBytes := []byte(fmt.Sprintf("%d", license.From))
	toBytes := []byte(fmt.Sprintf("%d", license.To))

	// Concatenate the items list (assuming it's strings)
	itemsBytes := []byte{}
	for _, item := range license.Items {
		itemsBytes = append(itemsBytes, []byte(item)...)
	}

	// Concatenate all data into a single byte slice
	concatenatedData := append(issuerBytes, licenseeBytes...)
	concatenatedData = append(concatenatedData, fromBytes...)
	concatenatedData = append(concatenatedData, toBytes...)
	concatenatedData = append(concatenatedData, itemsBytes...)

	return concatenatedData
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
