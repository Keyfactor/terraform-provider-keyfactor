package keyfactor

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	rsa2 "crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/rand"
	"net"
	"net/url"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"github.com/Keyfactor/keyfactor-go-client/v3/api"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/spbsoluble/go-pkcs12"
)

var (
	lowerCharSet   = "abcdedfghijklmnopqrst"
	upperCharSet   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	specialCharSet = "!@#$%&*"
	numberSet      = "0123456789"
	allCharSet     = lowerCharSet + upperCharSet + numberSet
)

func generatePassword(passwordLength, minSpecialChar, minNum, minUpperCase int) string {
	var password strings.Builder

	//Set special character
	for i := 0; i < minSpecialChar; i++ {
		random := rand.Intn(len(specialCharSet))
		password.WriteString(string(specialCharSet[random]))
	}

	//Set numeric
	for i := 0; i < minNum; i++ {
		random := rand.Intn(len(numberSet))
		password.WriteString(string(numberSet[random]))
	}

	//Set uppercase
	for i := 0; i < minUpperCase; i++ {
		random := rand.Intn(len(upperCharSet))
		password.WriteString(string(upperCharSet[random]))
	}

	remainingLength := passwordLength - minSpecialChar - minNum - minUpperCase
	for i := 0; i < remainingLength; i++ {
		random := rand.Intn(len(allCharSet))
		password.WriteString(string(allCharSet[random]))
	}
	inRune := []rune(password.String())
	rand.Shuffle(
		len(inRune), func(i, j int) {
			inRune[i], inRune[j] = inRune[j], inRune[i]
		},
	)
	return string(inRune)
}

func expandSubject(subject string) (
	types.String,
	types.String,
	types.String,
	types.String,
	types.String,
	types.String,
) {
	var (
		cn string
		ou string
		o  string
		l  string
		st string
		c  string
	)
	if subject != "" {
		subjectFields := strings.Split(subject, ",") // Separate subject fields into slices
		for _, field := range subjectFields {        // Iterate and assign slices to associated map
			if strings.Contains(field, "CN=") {
				//result["subject_common_name"] = types.String{Value: strings.Replace(field, "CN=", "", 1)}
				cn = strings.Replace(field, "CN=", "", 1)
			} else if strings.Contains(field, "OU=") {
				//result["subject_organizational_unit"] = types.String{Value: strings.Replace(field, "OU=", "", 1)}
				ou = strings.Replace(field, "OU=", "", 1)
			} else if strings.Contains(field, "C=") {
				//result["subject_country"] = types.String{Value: strings.Replace(field, "C=", "", 1)}
				c = strings.Replace(field, "C=", "", 1)
			} else if strings.Contains(field, "L=") {
				//result["subject_locality"] = types.String{Value: strings.Replace(field, "L=", "", 1)}
				l = strings.Replace(field, "L=", "", 1)
			} else if strings.Contains(field, "ST=") {
				//result["subject_state"] = types.String{Value: strings.Replace(field, "ST=", "", 1)}
				st = strings.Replace(field, "ST=", "", 1)
			} else if strings.Contains(field, "O=") {
				//result["subject_organization"] = types.String{Value: strings.Replace(field, "O=", "", 1)}
				o = strings.Replace(field, "O=", "", 1)
			}
		}
	}
	return types.String{Value: cn}, types.String{Value: ou}, types.String{Value: o}, types.String{Value: l}, types.String{Value: st}, types.String{Value: c}
}

func flattenSubject(subject string) types.Object {
	data := make(map[string]string) // Inner subject interface is a string mapped interface
	if subject != "" {
		subjectFields := strings.Split(subject, ",") // Separate subject fields into slices
		for _, field := range subjectFields {        // Iterate and assign slices to associated map
			if strings.Contains(field, "CN=") {
				//result["subject_common_name"] = types.String{Value: strings.Replace(field, "CN=", "", 1)}
				data["subject_common_name"] = strings.Replace(field, "CN=", "", 1)
			} else if strings.Contains(field, "OU=") {
				//result["subject_organizational_unit"] = types.String{Value: strings.Replace(field, "OU=", "", 1)}
				data["subject_organizational_unit"] = strings.Replace(field, "OU=", "", 1)
			} else if strings.Contains(field, "C=") {
				//result["subject_country"] = types.String{Value: strings.Replace(field, "C=", "", 1)}
				data["subject_country"] = strings.Replace(field, "C=", "", 1)
			} else if strings.Contains(field, "L=") {
				//result["subject_locality"] = types.String{Value: strings.Replace(field, "L=", "", 1)}
				data["subject_locality"] = strings.Replace(field, "L=", "", 1)
			} else if strings.Contains(field, "ST=") {
				//result["subject_state"] = types.String{Value: strings.Replace(field, "ST=", "", 1)}
				data["subject_state"] = strings.Replace(field, "ST=", "", 1)
			} else if strings.Contains(field, "O=") {
				//result["subject_organization"] = types.String{Value: strings.Replace(field, "O=", "", 1)}
				data["subject_organization"] = strings.Replace(field, "O=", "", 1)
			}
		}

	}
	result := types.Object{
		Attrs: map[string]attr.Value{
			"subject_common_name":         types.String{Value: data["subject_common_name"]},
			"subject_locality":            types.String{Value: data["subject_locality"]},
			"subject_organization":        types.String{Value: data["subject_organization"]},
			"subject_state":               types.String{Value: data["subject_state"]},
			"subject_country":             types.String{Value: data["subject_country"]},
			"subject_organizational_unit": types.String{Value: data["subject_organizational_unit"]},
		},
		AttrTypes: map[string]attr.Type{
			"subject_common_name":         types.StringType,
			"subject_locality":            types.StringType,
			"subject_organization":        types.StringType,
			"subject_state":               types.StringType,
			"subject_country":             types.StringType,
			"subject_organizational_unit": types.StringType,
		},
	}

	return result
}

func flattenMetadata(metadata interface{}) types.Map {
	data := make(map[string]string)
	if metadata != nil {
		for k, v := range metadata.(map[string]interface{}) {
			data[k] = v.(string)
		}
	}

	result := types.Map{
		Elems:    map[string]attr.Value{},
		ElemType: types.StringType,
	}
	for k, v := range data {
		result.Elems[k] = types.String{Value: v}
	}

	//check if elems is empty
	if len(result.Elems) == 0 {
		result.Null = true
	}
	return result
}

// DNSSANStoTerraform converts a slice of DNS SANs (Subject Alternative Names) into a Terraform-compatible
// `types.List`. The function can either allow duplicates or ensure unique entries based on the
// `allowDuplicates` parameter.
//
// Parameters:
//   - sans: A slice of strings representing the DNS SANs to be converted.
//   - allowDuplicates: A boolean flag indicating whether duplicates should be preserved in the result.
//
// Returns:
//   - A `types.List` where each element is a Terraform `types.String` value representing a DNS SAN.
//     If `allowDuplicates` is false, the list contains only unique DNS SAN strings.
func DNSSANStoTerraform(sans []string, allowDuplicates bool) types.List {
	result := types.List{
		ElemType: types.StringType,
		Elems:    []attr.Value{},
		Null:     true,
	}

	// Return result with duplicates
	if allowDuplicates {
		for _, dns := range sans {
			result.Elems = append(result.Elems, types.String{Value: dns})
			result.Null = false
		}
		return result
	}

	// Return result without duplicates
	uniqueSans := make(map[string]struct{})
	for _, dns := range sans {
		if _, exists := uniqueSans[dns]; !exists {
			uniqueSans[dns] = struct{}{}
			result.Elems = append(result.Elems, types.String{Value: dns})
			result.Null = false
		}
	}
	return result
}

// IPSANStoTerraform converts a slice of IP SANs (Subject Alternative Names) into a Terraform-compatible
// `types.List`. The function can either allow duplicates or ensure unique entries based on the
// `allowDuplicates` parameter.
//
// Parameters:
//   - ips: A slice of `net.IP` values representing the IP SANs to be converted.
//   - allowDuplicates: A boolean flag indicating whether duplicates should be preserved in the result.
//
// Returns:
//   - A `types.List` where each element is a Terraform `types.String` value representing an IP SAN.
//     If `allowDuplicates` is false, the list contains only unique IP SAN strings. Each `net.IP` value
//     is properly converted into a string format (e.g., IPv4 or IPv6).
func IPSANStoTerraform(ips []net.IP, allowDuplicates bool) types.List {
	result := types.List{
		ElemType: types.StringType,
		Elems:    []attr.Value{},
		Null:     true,
	}

	// Return result with duplicates
	if allowDuplicates {
		for _, ip := range ips {
			result.Elems = append(result.Elems, types.String{Value: ip.String()})
			result.Null = false
		}
		return result
	}

	// Return result without duplicates
	uniqueIps := make(map[string]struct{})
	for _, ip := range ips {
		if _, exists := uniqueIps[ip.String()]; !exists {
			uniqueIps[ip.String()] = struct{}{}
			result.Elems = append(result.Elems, types.String{Value: ip.String()})
			result.Null = false
		}
	}
	return result
}

// URISANStoTerraform converts a slice of URI SANs (Subject Alternative Names) into a Terraform-compatible
// `types.List`. The function can either allow duplicates or ensure unique entries based on the
// `allowDuplicates` parameter.
//
// If any of the elements in the input slice is `nil`, those entries are ignored.
//
// Parameters:
//   - uris: A slice of pointers to `url.URL` representing the URI SANs to be converted.
//   - allowDuplicates: A boolean flag indicating whether duplicates should be preserved in the result.
//
// Returns:
//   - A `types.List` where each element is a Terraform `types.String` value representing a URI SAN.
//     If `allowDuplicates` is false, the list contains only unique URI SAN strings. Nil values in the
//     input slice are ignored.
func URISANStoTerraform(uris []*url.URL, allowDuplicates bool) types.List {
	result := types.List{
		ElemType: types.StringType,
		Elems:    []attr.Value{},
		Null:     true,
	}

	// Return result with duplicates
	if allowDuplicates {
		for _, uri := range uris {
			if uri != nil { // Check for nil to prevent possible null pointer dereference
				result.Elems = append(result.Elems, types.String{Value: uri.String()})
				result.Null = false
			}
		}
		return result
	}

	// Return result without duplicates
	uniqueUris := make(map[string]struct{})
	for _, uri := range uris {
		if uri != nil { // Check for nil before referencing uri.String()
			if _, exists := uniqueUris[uri.String()]; !exists {
				uniqueUris[uri.String()] = struct{}{}
				result.Elems = append(result.Elems, types.String{Value: uri.String()})
				result.Null = false
			}
		}
	}
	return result
}

func unescapeJSON(jsonData string) ([]byte, error) {
	unescapedJSON, err := strconv.Unquote(jsonData)
	if err != nil {
		return []byte(jsonData), err
	}
	return []byte(unescapedJSON), nil
}

func flattenEnrollmentFields(efs []api.TemplateEnrollmentFields) types.List {

	result := types.List{
		ElemType: types.MapType{},
		Elems:    []attr.Value{},
	}
	for _, ef := range efs {
		var options []attr.Value
		for _, op := range ef.Options {
			options = append(
				options, types.String{
					Value: op,
				},
			)
		}
		result.Elems = append(
			result.Elems, types.Map{
				ElemType: types.StringType,
				Elems: map[string]attr.Value{
					"id":   types.Int64{Value: int64(ef.Id)},
					"name": types.String{Value: ef.Name},
					"type": types.String{Value: strconv.Itoa(ef.DataType)},
					"options": types.List{
						Elems:    options,
						ElemType: types.StringType,
					},
				},
			},
		)
	}

	return result
}

// parsePrivateKey encodes a private key (RSA, ECDSA, or ED25519) into a PEM-formatted string.
//
// This function takes a private key as an interface and determines its type (e.g., RSA, ECDSA, ED25519).
// Once the type is identified, it converts the key into its appropriate PEM-encoded representation.
//
// Parameters:
//   - ctx: The context for logging and diagnostics within the function.
//   - pkey: The private key as an interface{} that will be processed and encoded.
//
// Supported Private Key Types:
//   - *rsa.PrivateKey: Encoded as "RSA PRIVATE KEY"
//   - *ecdsa.PrivateKey: Encoded as "EC PRIVATE KEY"
//   - ed25519.PrivateKey: Encoded as "OPENSSH PRIVATE KEY"
//
// Unsupported key types will result in a warning log but will not cause the function to fail.
//
// Returns:
//   - (string): A PEM-formatted string representing the private key, or an empty string if the key
//     cannot be processed.
//   - (diag.Diagnostics): A diagnostic object that may contain warnings or relevant logs.
func parsePrivateKey(ctx context.Context, pkey interface{}) (string, diag.Diagnostics) {
	var pkeyPEM string
	diags := diag.Diagnostics{}

	switch key := pkey.(type) {
	case *rsa2.PrivateKey:
		tflog.Debug(ctx, "Recovered RSA private key from Keyfactor Command.")
		if buf := x509.MarshalPKCS1PrivateKey(key); len(buf) > 0 {
			tflog.Debug(ctx, "Encoding RSA private key from Keyfactor Command.")
			pkeyPEM = string(
				pem.EncodeToMemory(
					&pem.Block{
						Type:  "RSA PRIVATE KEY",
						Bytes: buf,
					},
				),
			)
		} else {
			tflog.Warn(ctx, "Empty RSA private key recovered from Keyfactor Command.")
			diags.AddWarning(
				"Empty private key recovered",
				"Keyfactor Command returned an empty private key. This may be due to the private key being in a format that is not supported by Terraform. Please check the Keyfactor Command logs for more information.",
			)
			break
		}
	case *ecdsa.PrivateKey:
		tflog.Debug(ctx, "Recovered ECC private key from Keyfactor Command.")
		buf, err := x509.MarshalECPrivateKey(key)
		if err == nil && len(buf) > 0 {
			tflog.Debug(ctx, "Encoding ECC private key from Keyfactor Command.")
			pkeyPEM = string(
				pem.EncodeToMemory(
					&pem.Block{
						Type:  "EC PRIVATE KEY",
						Bytes: buf,
					},
				),
			)
		} else if err != nil {
			tflog.Warn(ctx, "Failed to marshal ECC private key: "+err.Error())
		}
	case ed25519.PrivateKey:
		tflog.Debug(ctx, "Recovered Ed25519 private key from Keyfactor Command.")
		buf := key.Seed()
		if len(buf) > 0 {
			tflog.Debug(ctx, "Encoding Ed25519 private key from Keyfactor Command.")
			pkeyPEM = string(
				pem.EncodeToMemory(
					&pem.Block{
						Type:  "OPENSSH PRIVATE KEY",
						Bytes: buf,
					},
				),
			)
		} else {
			tflog.Warn(ctx, "Empty Ed25519 private key recovered from Keyfactor Command.")
			diags.AddWarning(
				"Empty private key recovered",
				"Keyfactor Command returned an empty private key. This may be due to the private key being in a format that is not supported by Terraform. Please check the Keyfactor Command logs for more information.",
			)
		}
	default:
		tflog.Warn(ctx, "Unsupported private key type provided.")
		diags.AddError(
			"Unsupported private key type",
			fmt.Sprintf("Unsupported private key type %s provided.", reflect.TypeOf(key)),
		)
	}

	return pkeyPEM, diags
}

// recoverPrivateKeyFromKeyfactorCommand retrieves the private key, leaf certificate, and certificate chain
// for a specific certificate from Keyfactor Command.
//
// This function communicates with the Keyfactor Command API to recover a private key and its associated
// certificate data. It validates input parameters, handles potential errors during data retrieval, and converts
// the resulting data into PEM-encoded strings.
//
// Parameters:
//   - ctx: The context for logging and diagnostics during the function's execution.
//   - certId: The ID of the certificate for which private key recovery is requested.
//   - collectionId: The ID of the Keyfactor collection in which the certificate resides.
//   - lookupPassword: The password for accessing the private key in Keyfactor Command.
//   - client: A Keyfactor API client used to retrieve the certificate and its private key.
//
// Returns:
//   - (string): A PEM-encoded private key if successfully recovered, otherwise an empty string.
//   - (string): A PEM-encoded certificate (leaf certificate) if successfully recovered, otherwise an empty string.
//   - (string): A PEM-encoded certificate chain (if available), otherwise an empty string.
func recoverPrivateKeyFromKeyfactorCommand(
	ctx context.Context,
	certId int,
	collectionId int,
	lookupPassword string,
	client *api.Client,
) (string, string, string, diag.Diagnostics) {
	diags := diag.Diagnostics{}

	if client == nil {
		tflog.Error(ctx, "Keyfactor Command client is nil. Unable to recover private key for certificate.")
		diags.AddError(
			"Error recovering private key from Keyfactor Command",
			"Keyfactor Command client is nil.",
		)
		return "", "", "", diags
	}

	tflog.Info(ctx, "Attempting to recover private key from Keyfactor Command.")
	pkey, leaf, certChain, recErr := client.RecoverCertificate(certId, "", "", "", lookupPassword, collectionId)
	if recErr != nil {
		errMsg := fmt.Sprintf(
			"Unable to recover private key for certificate '%v' from Keyfactor Command: %v",
			certId,
			recErr.Error(),
		)
		tflog.Error(ctx, errMsg)
		diags.AddError("Error recovering private key from Keyfactor Command", errMsg)
		return "", "", "", diags
	}

	if pkey == nil {
		errMsg := fmt.Sprintf(
			"Private key not available for certificate '%v' from Keyfactor Command.", certId,
		)
		tflog.Error(ctx, errMsg)
		diags.AddError("No private key returned", errMsg)
		return "", "", "", diags
	}

	tflog.Info(ctx, "Private key successfully recovered from Keyfactor Command.")
	pkeyPEM, pkeyDiags := parsePrivateKey(ctx, pkey)
	if pkeyDiags.HasError() {
		errMsg := "Error parsing private key from Keyfactor Command."
		tflog.Error(ctx, errMsg)
		diags.AddError(errMsg, errMsg)
		return "", "", "", diags
	}

	certPEM, _ := encodeCertificate(ctx, leaf, certId)

	chainPEM := encodeCertificateChain(ctx, certChain, certId)

	return pkeyPEM, certPEM, chainPEM, diags
}

// encodeCertificate encodes a provided certificate into a PEM-formatted string and returns it.
//
// This function supports the following types for the `leaf` parameter:
//   - *x509.Certificate: Encodes the raw certificate bytes into PEM format.
//   - *string: Returns the string as-is, assuming it is already PEM-formatted.
//   - *[]byte: Wraps the byte slice into a PEM block and encodes it.
//
// If the input is invalid (nil, empty, or unsupported type), the function logs
// appropriate warnings and returns an error indicating the issue.
//
// Parameters:
//   - ctx: The context for logging using tflog.
//   - leaf: The certificate data to be converted to PEM format. Can be one of:
//     *x509.Certificate, *string, or *[]byte.
//   - certId: An integer identifier for the certificate, used for logging purposes.
//
// Returns:
//   - string: The PEM-formatted certificate string, or an empty string if an error occurs.
//   - error: An error describing any issue with the input or processing.
//
// Example Usage:
//
//	// Using *x509.Certificate as input
//	cert := &x509.Certificate{Raw: []byte{0x30, 0x82, 0x02}} // Example certificate
//	pemString, err := encodeCertificate(ctx, cert, 12345)
//	if err != nil {
//	    fmt.Println("Error:", err)
//	} else {
//	    fmt.Println("PEM Certificate:", pemString)
//	}
//
//	// Using *string as input
//	certString := "-----BEGIN CERTIFICATE-----\nMIIBIjANBgkq...\n-----END CERTIFICATE-----"
//	pemString, err := encodeCertificate(ctx, &certString, 12345)
//	if err != nil {
//	    fmt.Println("Error:", err)
//	} else {
//	    fmt.Println("PEM Certificate:", pemString)
//	}
//
//	// Using *[]byte as input
//	certBytes := []byte{0x30, 0x82, 0x02} // Example byte slice
//	pemString, err := encodeCertificate(ctx, &certBytes, 12345)
//	if err != nil {
//	    fmt.Println("Error:", err)
//	} else {
//	    fmt.Println("PEM Certificate:", pemString)
//	}
func encodeCertificate(ctx context.Context, leaf any, certId int) (string, error) {
	if leaf == nil {
		err := fmt.Errorf("no leaf certificate provided for certificate %v", certId)
		tflog.Warn(ctx, err.Error())
		return "", err
	}

	var rawBytes []byte
	switch v := leaf.(type) {
	case *x509.Certificate:
		tflog.Debug(ctx, "Leaf certificate provided as *x509.Certificate.")
		rawBytes = v.Raw
	case *string:
		tflog.Debug(ctx, "Leaf certificate provided as *string.")
		if v != nil && *v != "" {
			return *v, nil // Return as-is, assuming it's already in PEM format
		}
	case *[]byte:
		tflog.Debug(ctx, "Leaf certificate provided as *[]byte.")
		if v != nil && len(*v) > 0 {
			rawBytes = *v
		}
	default:
		err := fmt.Errorf("invalid leaf type provided for certificate %v", certId)
		tflog.Warn(ctx, err.Error())
		return "", err
	}

	if len(rawBytes) == 0 {
		err := fmt.Errorf("empty or invalid data for certificate %v", certId)
		tflog.Warn(ctx, err.Error())
		return "", err
	}

	pemString := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rawBytes}))
	tflog.Debug(ctx, "Certificate successfully encoded to PEM format.")
	return pemString, nil
}

func encodeCertificateChain(ctx context.Context, certChain []*x509.Certificate, certId int) string {
	if certChain == nil {
		tflog.Warn(
			ctx, fmt.Sprintf(
				"No certificate chain returned from Keyfactor Command for certificate %v.", certId,
			),
		)
		return ""
	}

	var chainPEM string
	tflog.Debug(ctx, "Recovering certificate chain from Keyfactor Command.")
	for i, cert := range certChain {
		if cert == nil {
			continue
		}
		tflog.Trace(ctx, fmt.Sprintf("Encoding chain certificate %d", i))
		chainPEM += string(
			pem.EncodeToMemory(
				&pem.Block{
					Type:  "CERTIFICATE",
					Bytes: cert.Raw,
				},
			),
		)
	}
	return chainPEM
}

func flattenTemplateRegexes(regexes []api.TemplateRegex) types.List {
	result := types.List{
		ElemType: types.StringType,
		Elems:    []attr.Value{},
	}
	for _, regex := range regexes {
		result.Elems = append(result.Elems, types.String{Value: regex.RegEx})
	}
	return result
}

func flattenAllowedRequesters(requesters []string) types.List {
	result := types.List{
		ElemType: types.StringType,
		Elems:    []attr.Value{},
	}

	if len(requesters) > 0 {
		for _, requester := range requesters {
			result.Elems = append(result.Elems, types.String{Value: requester})
		}
	}

	return result
}

func isNullString(s string) bool {
	switch s {
	case "", "null":
		return true
	default:
		return false
	}
}

func isNullId(i int) bool {
	if i <= 0 {
		return true
	}
	return false
}

// downloadCertificateFromKeyfactorCommand retrieves the leaf certificate and certificate chain
// for a specific certificate from Keyfactor Command.
//
// This function communicates with the Keyfactor Command API to download the requested certificate
// and its chain. It handles errors gracefully, ensuring that partial data (such as the leaf certificate
// or chain) is returned if available.
//
// Parameters:
//   - ctx: The context for logging and diagnostics during execution.
//   - certId: The ID of the certificate to be downloaded.
//   - collectionId: The ID of the Keyfactor collection to which the certificate belongs (currently not used).
//   - client: A Keyfactor API client for interacting with the Keyfactor Command system.
//
// Returns:
//   - (string): The PEM-encoded leaf certificate if successfully retrieved, otherwise an empty string.
//   - (string): The PEM-encoded certificate chain if successfully retrieved, otherwise an empty string.
//   - (diag.Diagnostics): Diagnostics information, including errors or warnings encountered during the process.
//
// Behavior:
//   - Returns an error if the client is nil or the certificate cannot be downloaded.
//   - Logs warnings if only partial data (e.g., leaf without chain) is retrieved.
//   - Uses helper functions `encodeCertificate` and `encodeCertificateChain` to convert the certificates into PEM format.
//
// Notes:
//   - Collection ID is currently a placeholder and not used in the function.
//   - The function ensures partial success when either the leaf certificate or chain is available.
func downloadCertificateFromKeyfactorCommand(
	ctx context.Context,
	certId int,
	collectionId int,
	client *api.Client,
) (string, string, diag.Diagnostics) {
	diags := diag.Diagnostics{}
	if client == nil {
		tflog.Error(ctx, "Keyfactor Command client is nil. Unable to download the certificate.")
		diags.AddError("Certificate download error", "Keyfactor Command client is nil.")
		return "", "", diags
	}

	tflog.Debug(ctx, "Downloading certificate and chain from Keyfactor Command.")
	leaf, chain, dErr := client.DownloadCertificate(certId, "", "", "") // TODO: Add collection ID support
	if dErr != nil {
		errMsg := "Error downloading certificate from Keyfactor Command: " + dErr.Error()
		if leaf == nil && chain == nil {
			tflog.Error(ctx, errMsg)
			diags.AddError("Certificate download error", errMsg)
			return "", "", diags
		}
		tflog.Warn(ctx, errMsg)
		diags.AddWarning("Certificate download warning", errMsg)
	}

	leafPEM, leafErr := encodeCertificate(ctx, leaf, certId)
	if leafErr != nil {
		errMsg := "unable to encode leaf certificate from Keyfactor Command: " + leafErr.Error()
		if chain == nil {
			tflog.Error(ctx, errMsg)
			diags.AddError("Certificate download error", errMsg)
			return "", "", diags
		}

		tflog.Warn(ctx, errMsg)
	}
	chainPEM := encodeCertificateChain(ctx, chain, certId)

	return leafPEM, chainPEM, diags
}

//func downloadCertificate(id int, collectionId int, kfClient *api.Client, password string, csrEnrollment bool) (
//	string,
//	string,
//	string,
//	error,
//) {
//	log.Printf("[DEBUG] enter downloadCertificate")
//	log.Printf("[INFO] Downloading certificate with ID: %d", id)
//
//	req := api.GetCertificateContextArgs{
//		Id: id,
//	}
//	if collectionId > 0 {
//		log.Printf("[INFO] Downloading certificate '%d' from Collection ID: %d", id, collectionId)
//		req.CollectionId = &collectionId
//	}
//	log.Printf("[INFO] Downloading certificate from Keyfactor Command")
//	log.Printf("[DEBUG] Request: %+v", req)
//	certificateContext, err := kfClient.GetCertificateContext(&req)
//	if err != nil {
//		log.Printf("[ERROR] Error downloading certificate: %s", err)
//		return "", "", "", err
//	}
//
//	log.Printf("[INFO] Looking up certificate template with ID: %d", certificateContext.TemplateId)
//	template, err := kfClient.GetTemplate(certificateContext.TemplateId)
//	if err != nil {
//		log.Printf(
//			"[ERROR] Error looking up certificate template: %s returning integer value rater than common name",
//			err,
//		)
//		template = nil
//	}
//
//	recoverable := false
//
//	if template == nil || template.KeyRetention != "None" {
//		recoverable = true
//	}
//
//	var privPem []byte
//	var leafPem []byte
//	var chainPem []byte
//
//	if recoverable && !csrEnrollment {
//		log.Printf("[INFO] Recovering certificate with ID: %d", id)
//		//priv, leaf, chain, rErr := kfClient.RecoverCertificate(id, "", "", "", password)
//		priv, leaf, chain, rErr := kfClient.RecoverCertificate(id, "", "", "", password, collectionId)
//		if rErr != nil {
//			log.Printf("[ERROR] Error recovering certificate: %s", rErr)
//			return "", "", "", rErr
//		}
//
//		// Encode DER to PEM
//		log.Printf("[DEBUG] Encoding certificate to PEM")
//		leafPem = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})
//		log.Printf("[DEBUG] Encoding chain to PEM")
//		for _, i := range chain {
//			chainPem = append(chainPem, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: i.Raw})...)
//		}
//		log.Printf("[DEBUG] Chain PEM: %s", chainPem)
//
//		log.Printf("[DEBUG] Encoding private key to PEM")
//		// Figure out the format of the private key, then encode it to PEM
//
//		log.Printf("[DEBUG] Private Key Type: %T", priv)
//		rsa, ok := priv.(*rsa2.PrivateKey)
//		if ok {
//			log.Printf("[INFO] Private Key is RSA for certificate ID: %d", id)
//			buf := x509.MarshalPKCS1PrivateKey(rsa)
//			if len(buf) > 0 {
//				privPem = pem.EncodeToMemory(&pem.Block{Bytes: buf, Type: "RSA PRIVATE KEY"})
//			}
//		}
//
//		if privPem == nil {
//			log.Printf("[INFO] Private Key is not RSA for certificate ID: %d attempting to parse ECC key", id)
//			ecc, ok := priv.(*ecdsa.PrivateKey)
//			if ok {
//				log.Printf("[INFO] Private Key is ECDSA for certificate ID: %d", id)
//				buf, _ := x509.MarshalECPrivateKey(ecc)
//				if len(buf) > 0 {
//					privPem = pem.EncodeToMemory(&pem.Block{Bytes: buf, Type: "EC PRIVATE KEY"})
//				}
//			}
//		}
//	} else {
//		log.Printf("[INFO] Downloading certificate with ID: %d", id)
//		leaf, chain, dlErr := kfClient.DownloadCertificate(id, "", "", "")
//		if dlErr != nil {
//			log.Printf("[ERROR] Error downloading certificate: %s", dlErr)
//			return "", "", "", err
//		}
//
//		// Encode DER to PEM
//		log.Printf("[DEBUG] Encoding certificate to PEM")
//		leafPem = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})
//		log.Printf("[DEBUG] Certificate PEM: %s", leafPem)
//		log.Printf("[DEBUG] Encoding chain to PEM")
//		// iterate through chain in reverse order
//		for i := len(chain) - 1; i >= 0; i-- {
//			// check if current cert is the leaf cert
//			if chain[i].SerialNumber.Cmp(leaf.SerialNumber) == 0 {
//				continue
//			}
//			chainPem = append(chainPem, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: chain[i].Raw})...)
//		}
//		log.Printf("[DEBUG] Chain PEM: %s", chainPem)
//	}
//
//	log.Printf("[DEBUG] exit downloadCertificate")
//	return string(leafPem), string(chainPem), string(privPem), nil
//}

func terraformBoolToGoBool(tfBool string) (bool, error) {
	tfBool = strings.ToLower(tfBool)
	if tfBool == "true" {
		return true, nil
	} else if tfBool == "false" {
		return false, nil
	}
	return false, fmt.Errorf("invalid Terraform bool: %s", tfBool)
}

func parseProperties(properties string) (types.Map, types.String, types.String, types.Bool, diag.Diagnostics) {
	var (
		serverUsername types.String
		serverPassword types.String
		//storePassword  types.String
		serverUseSsl types.Bool
		diags        diag.Diagnostics
	)
	propElems := make(map[string]attr.Value)
	propsObj := make(map[string]interface{})
	if properties != "" {
		//convert JSON string to map
		unescapedJSON, _ := unescapeJSON(properties)
		jsonErr := json.Unmarshal(unescapedJSON, &propsObj)
		if jsonErr != nil {
			diags.AddError(
				ERR_SUMMARY_CERT_STORE_READ,
				"Error reading certificate store: %s"+jsonErr.Error(),
			)
			return types.Map{}, types.String{Value: ""}, types.String{Value: ""}, types.Bool{Value: false}, diags
		}
	}

	for k, v := range propsObj {
		switch k {
		case "ServerUsername":
			serverUsername = types.String{Value: v.(string)}
		case "ServerPassword":
			serverPassword = types.String{Value: v.(string)}
		case "ServerUseSsl":
			// Convert terraform True/False to bool true/false
			val, valErr := terraformBoolToGoBool(v.(string))
			if valErr != nil {
				val = true // Default to true if we can't convert
			}
			serverUseSsl = types.Bool{Value: val}
		//case "StorePassword":
		//	storePassword = types.String{Value: v.(string)} //TODO: Command doesn't seem to return anything for this as of 10.x
		default:
			propElems[k] = types.String{Value: v.(string)}
		}
	}

	return types.Map{ElemType: types.StringType, Elems: propElems}, serverUsername, serverPassword, serverUseSsl, diags
}

func parseStorePassword(sPassword *api.StorePasswordConfig) types.String {
	if sPassword == nil {
		return types.String{Value: ""}
	} else {
		if sPassword.Value != nil {
			return types.String{Value: *sPassword.Value}
		} else {
			return types.String{Value: ""}
		}
	}
}

func isGUID(input string) bool {
	guidPattern := `^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$`
	match, _ := regexp.MatchString(guidPattern, input)
	return match
}

func isNullList(input types.List) bool {
	if input.Elems == nil || len(input.Elems) == 0 {
		return true
	}
	return false
}

func checkListNull(tfList types.List, apiResponseList []interface{}) bool {
	if tfList.IsNull() && len(apiResponseList) == 0 {
		return true
	}
	return false
}

func sortInSameOrder(unsortedList, sortedList []string) []string {
	// Sort unsortedList in the same order as sortedList
	// This is needed because the API returns the list in a different order than the order we sent it in
	// This is needed for the terraform import command to work
	var sorted []string

	//if lists are not the same length don't waste the effort and return unsortedList
	if len(unsortedList) != len(sortedList) {
		return unsortedList
	}

	for _, v := range sortedList {
		for _, u := range unsortedList {
			if v == u {
				sorted = append(sorted, u)
			}
		}
	}
	return sorted
}

func LogFunctionEntry(ctx context.Context, methodName string) {
	tflog.Debug(ctx, fmt.Sprintf("entered: %s", methodName))
	return
}

func LogFunctionExit(ctx context.Context, methodName string) {
	tflog.Debug(ctx, fmt.Sprintf("exited: %s", methodName))
	return
}

func LogFunctionCall(ctx context.Context, methodName string) {
	tflog.Debug(ctx, fmt.Sprintf("calling: %s", methodName))
	return
}

func LogFunctionReturned(ctx context.Context, methodName string) {
	tflog.Debug(ctx, fmt.Sprintf("returned: %s", methodName))
	return
}

// unpackPkcs12 extracts the private key, certificate, and CA certificates from a PKCS#12/PFX file.
// Parameters:
//   - pfxData: The byte slice containing the PKCS#12/PFX file data.
//   - password: The password used for decrypting the PKCS#12/PFX file.
//
// Returns:
//   - privateKey: The private key extracted from the PFX file, in PEM format.
//   - certificate: The certificate extracted from the PFX file, in PEM format.
//   - caCertificates: A slice of CA certificates extracted from the PFX file, in PEM format (if any).
//   - err: An error that describes why the unpacking failed, if any.
func unpackPkcs12(pfxData interface{}, password string) (
	privateKey, certificate string,
	caCertificates []string,
	err error,
) {
	// Convert pfxData to []byte, if necessary
	var pfxBytes []byte
	switch v := pfxData.(type) {
	case string:
		pfxBytes = []byte(v) // Convert string to []byte
	case []byte:
		pfxBytes = v
	default:
		err = fmt.Errorf("invalid pfxData type: expected string or []byte, got %T", pfxData)
		return
	}

	// Decode the PKCS#12 data
	parsedKey, parsedCert, parsedCAs, pkcs12Err := pkcs12.DecodeChain(pfxBytes, password)
	if pkcs12Err != nil {
		err = fmt.Errorf("failed to decode PKCS#12 data: %v", pkcs12Err)
		return
	}

	// PEM-encode the private key
	privateKeyBlock, keyErr := encodePrivateKey(parsedKey)
	if keyErr != nil {
		err = fmt.Errorf("failed to encode private key: %v", keyErr)
		return
	}
	privateKey = string(pem.EncodeToMemory(privateKeyBlock))

	// PEM-encode the certificate
	certificateBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: parsedCert.Raw,
	}
	certificate = string(pem.EncodeToMemory(certificateBlock))

	// PEM-encode the CA certificates (if any)
	for _, caCert := range parsedCAs {
		caCertBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: caCert.Raw,
		}
		caCertificates = append(caCertificates, string(pem.EncodeToMemory(caCertBlock)))
	}

	return privateKey, certificate, caCertificates, nil
}

// encodePrivateKey determines the type of private key (RSA or ECDSA) and encodes it as a PEM block.
// Parameters:
//   - key: The private key to encode.
//
// Returns:
//   - pemBlock: The PEM block representation of the private key.
//   - err: An error if the private key type is unsupported or invalid.
func encodePrivateKey(key interface{}) (*pem.Block, error) {
	switch k := key.(type) {
	case *rsa2.PrivateKey:
		return &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(k),
		}, nil
	case *ecdsa.PrivateKey:
		encodedKey, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, fmt.Errorf("failed to encode ECDSA private key: %v", err)
		}
		return &pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: encodedKey,
		}, nil
	case ed25519.PrivateKey:
		return &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: k,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported private key type: %T", key)
	}
}
