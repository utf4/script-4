package core

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
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

// Read license file
func ReadFile(filename string) (map[common.Address]License, error) {
	if filename == "" {
		filename = licenseFile
	}

	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("Failed to open file: %v at %v", err, licenseFile)
	}
	defer file.Close()

	bytes, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("Failed to read file: %v", err)
	}

	var licenses []LicenseReadFile
	err = json.Unmarshal(bytes, &licenses)
	if err != nil {
		return nil, fmt.Errorf("Failed to unmarshal JSON: %v", err)
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
			return nil, fmt.Errorf("Failed to parse 'From' field: %v", err)
		}

		to, err := strconv.ParseInt(licenseRF.To, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("Failed to parse 'To' field: %v", err)
		}

		license := License{
			Issuer:    licenseRF.Issuer,
			Licensee:  licenseRF.Licensee,
			From:      uint64(from),
			To:        uint64(to),
			Items:     licenseRF.Items,
			Signature: licenseRF.Signature,
		}

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

	return crypto.NewSignature(decodedSig), nil
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
	currentTime := uint64(time.Now().Unix())
	if license.From > currentTime || license.To < currentTime {
		return fmt.Errorf("Current time is outside the valid license period")
	}

	if !isLicenseForValidatorNode(license.Items) {
		return fmt.Errorf("License items do not include 'VN'")
	}
	if !isLicenseForLightningNode(license.Items) {
		return fmt.Errorf("License items do not include 'LN'")
	}

	signature, err := ConvertStringToSignature(license.Signature)
	if err != nil {
		return fmt.Errorf("Failed to convert string to signature: %v", err)
	}

	dataToSign := concatenateLicenseData(license)
	if !signature.Verify(dataToSign, license.Issuer) {
		return fmt.Errorf("Invalid license signature")
	}
	return nil
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
		return fmt.Errorf("No license found for the given licensee public key")
	}

	currentTime := uint64(time.Now().Unix())
	if license.From > currentTime || license.To < currentTime {
		verifiedLicenseCache[licensee] = false
		return fmt.Errorf("Current time is outside the valid license period")
	}

	dataToValidate := concatenateLicenseData(license)

	signature, err := ConvertStringToSignature(license.Signature)
	if err != nil {
		return fmt.Errorf("Failed to convert string to signature: %v", err)
	}
	if !signature.Verify(dataToValidate, license.Issuer) {
		verifiedLicenseCache[licensee] = false
		return fmt.Errorf("Invalid license signature:%v, %v, %v, %x", license.Issuer.Hex(), base64.StdEncoding.EncodeToString(signature.ToBytes()), dataToValidate, keccak256(dataToValidate))
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

func isLicenseForLightningNode(items []string) bool {
	for _, item := range items {
		if item == "LN" {
			return true
		}
	}
	return false
}

func concatenateLicenseData(license License) []byte {
	// Convert fields to byte slices or strings
	issuerBytes := []byte(strings.ToUpper(license.Issuer.Hex()))
	licenseeBytes := []byte(strings.ToUpper(license.Licensee.Hex()))
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
