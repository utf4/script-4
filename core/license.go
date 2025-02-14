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

func SetLicenseFile(filename string) {
	licenseFile = filename
}

// Read license file
func ReadFile(filename string) (map[common.Address]License, error) {
	if filename == "" {
		filename = licenseFile
	}

	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %v at %v", err, licenseFile)
	}
	defer file.Close()

	bytes, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %v", err)
	}

	var licenses []LicenseReadFile
	err = json.Unmarshal(bytes, &licenses)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %v", err)
	}

	licenseMap = make(map[common.Address]License)
	verifiedLicenseCache = make(map[common.Address]bool)

	for _, licenseRF := range licenses {
		from, err := strconv.ParseInt(licenseRF.From, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("failed to parse 'From' field: %v", err)
		}

		to, err := strconv.ParseInt(licenseRF.To, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("failed to parse 'To' field: %v", err)
		}

		license := License{
			Issuer:    licenseRF.Issuer,
			Licensee:  licenseRF.Licensee,
			From:      uint64(from),
			To:        uint64(to),
			Items:     licenseRF.Items,
			Signature: licenseRF.Signature,
		}

		// Validate licese before adding to the list
		if err = ValidateIncomingLicense(license); err != nil {
			return nil, fmt.Errorf("failed to validate license for licensee %v: %v", license.Licensee.Hex(), err)
		}

		licenseMap[license.Licensee] = license
	}

	return licenseMap, nil
}

func ParseAndFormatSignature(signBytes []byte) ([]byte, error) {
	// Validate signature length
	if len(signBytes) != 65 {
		return nil, fmt.Errorf("failed to validate signature length: expected 65 bytes, got %v", len(signBytes))
	}

	// Extract r, s, and v
	r := signBytes[:32]
	s := signBytes[32:64]
	v := signBytes[64]

	rArray := make([]byte, 32)
	sArray := make([]byte, 32)
	copy(rArray[32-len(r):], r)
	copy(sArray[32-len(s):], s)

	return append(append(rArray, sArray...), v), nil
}

func ConvertStringToSignature(signatureStr string) (*crypto.Signature, error) {
	// Decode signature string as encoded in base64
	decodedSig, err := base64.StdEncoding.DecodeString(signatureStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 signature: %v", err)
	}

	// Parse and format signature bytes
	signBytes, err := ParseAndFormatSignature(decodedSig)
	if err != nil {
		return nil, fmt.Errorf("failed to convert DER to raw signature: %v", err)
	}

	return crypto.NewSignature(signBytes), nil
}

func WriteLicenseFile(license License, filename string) error {
	if err := ValidateIncomingLicense(license); err != nil {
		return fmt.Errorf("failed to validate license: %v", err)
	}

	if filename == "" {
		filename = licenseFile
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

	if _, err = file.Write(licenseJSON); err != nil {
		return fmt.Errorf("failed to write license to file: %v", err)
	}

	if _, err = file.WriteString("\n"); err != nil {
		return fmt.Errorf("failed to write newline to file: %v", err)
	}

	licenseMap[license.Licensee] = license
	return nil
}

func ValidateIncomingLicense(license License) error {
	// Validate the license period
	currentTime := uint64(time.Now().Unix())
	if license.From > currentTime || license.To < currentTime {
		return fmt.Errorf("failed to validate license period")
	}

	// Validate the license items
	if !isLicenseForValidatorNode(license.Items) && !isLicenseForLightningNode(license.Items) {
		return fmt.Errorf("failed to validate license items: %v", license.Items)
	}

	// Convert string signature to the object
	signature, err := ConvertStringToSignature(license.Signature)
	if err != nil {
		return fmt.Errorf("failed to convert string to signature: %v", err)
	}

	// Verify license signature
	dataToVerify := concatenateLicenseData(license)
	isValid := signature.Verify(dataToVerify, license.Issuer)
	if isValid {
		fmt.Println("license signature is valid.")
		return nil
	}

	return fmt.Errorf("failed to validate license signature:: %v", license.Signature)
}

func ValidateLicense(licensee common.Address) error {
	// Check license cache
	if _, exists := verifiedLicenseCache[licensee]; exists {
		return nil
	}

	// Fetch license for the licensee public key
	license, exists := licenseMap[licensee]
	if !exists {
		return fmt.Errorf("failed to find any license for the given public key: %v", licensee)
	}

	currentTime := uint64(time.Now().Unix())
	if license.From > currentTime || license.To < currentTime {
		verifiedLicenseCache[licensee] = false
		return fmt.Errorf("current time is outside the valid license period")
	}

	// Convert string signature to the object
	signature, err := ConvertStringToSignature(license.Signature)
	if err != nil {
		return fmt.Errorf("failed to convert string to signature object: %v", err)
	}

	// Verify license signature
	dataToVerify := concatenateLicenseData(license)
	if isValid := signature.Verify(dataToVerify, license.Issuer); isValid {
		verifiedLicenseCache[licensee] = true
		return nil
	}

	return fmt.Errorf("failed to validate license signature")
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

	items := ""
	for _, item := range license.Items {
		items += item
	}

	// Construct data with Ethereum prefix format
	dataToVerify := issuer + licensee + from + to + items
	prefix := "\x19Ethereum Signed Message:\n" + strconv.Itoa(len(dataToVerify))
	return common.Bytes(prefix + dataToVerify)
}

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
