package cert

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"strings"
)

// ExtractCN extracts the Common Name (CN) from a certificate's Subject
func ExtractCN(cert *x509.Certificate) string {
	return extractDNComponent(cert.Subject, "CN")
}

// ExtractDNComponents extracts all components from a Distinguished Name
func ExtractDNComponents(subject pkix.Name) map[string][]string {
	components := make(map[string][]string)

	for _, rdns := range subject.Names {
		if strValue, ok := rdns.Value.(string); ok && len(strValue) > 0 {
			oidStr := rdns.Type.String()
			components[oidStr] = append(components[oidStr], strValue)
		}
	}

	// Handle legacy fields
	if len(subject.Country) > 0 {
		components["C"] = subject.Country
	}
	if len(subject.Organization) > 0 {
		components["O"] = subject.Organization
	}
	if len(subject.OrganizationalUnit) > 0 {
		components["OU"] = subject.OrganizationalUnit
	}
	if len(subject.Locality) > 0 {
		components["L"] = subject.Locality
	}
	if len(subject.Province) > 0 {
		components["ST"] = subject.Province
	}
	if subject.SerialNumber != "" {
		components["SERIALNUMBER"] = []string{subject.SerialNumber}
	}
	if len(subject.StreetAddress) > 0 {
		components["STREET"] = subject.StreetAddress
	}
	if len(subject.PostalCode) > 0 {
		components["POSTALCODE"] = subject.PostalCode
	}

	return components
}

// extractDNComponent extracts a specific component from a Distinguished Name
func extractDNComponent(subject pkix.Name, component string) string {
	// Try to find in Names slice first
	for _, rdn := range subject.Names {
		// Check if this is the CN attribute
		if component == "CN" {
			if rdn.Type.String() == "2.5.4.3" || rdn.Type.String() == "CN" {
				if cn, ok := rdn.Value.(string); ok {
					return cn
				}
			}
		}
	}

	// Legacy field check for CN
	if component == "CN" && len(subject.CommonName) > 0 {
		return subject.CommonName
	}

	// Check other legacy fields
	switch strings.ToUpper(component) {
	case "C":
		if len(subject.Country) > 0 {
			return subject.Country[0]
		}
	case "O":
		if len(subject.Organization) > 0 {
			return subject.Organization[0]
		}
	case "OU":
		if len(subject.OrganizationalUnit) > 0 {
			return subject.OrganizationalUnit[0]
		}
	case "L":
		if len(subject.Locality) > 0 {
			return subject.Locality[0]
		}
	case "ST":
		if len(subject.Province) > 0 {
			return subject.Province[0]
		}
	case "SERIALNUMBER":
		return subject.SerialNumber
	}

	return ""
}

// FormatDN formats a Distinguished Name as a string
func FormatDN(subject pkix.Name) string {
	var parts []string

	if cn := ExtractCN(&x509.Certificate{Subject: subject}); cn != "" {
		parts = append(parts, "CN="+cn)
	}
	if len(subject.Country) > 0 {
		parts = append(parts, "C="+subject.Country[0])
	}
	if len(subject.Organization) > 0 {
		parts = append(parts, "O="+subject.Organization[0])
	}
	if len(subject.OrganizationalUnit) > 0 {
		parts = append(parts, "OU="+subject.OrganizationalUnit[0])
	}
	if len(subject.Locality) > 0 {
		parts = append(parts, "L="+subject.Locality[0])
	}
	if len(subject.Province) > 0 {
		parts = append(parts, "ST="+subject.Province[0])
	}

	return strings.Join(parts, ", ")
}
