package cdoc2

import "strings"

// Labels are public container metadata, never passwords or symmetric keys.
// CDOC2 permits both human-readable labels and structured data: labels.
// Preserve an explicit label; use the certificate identity for unnamed locks.
func defaultRecipientLabel(r Recipient) string {
	if r.Certificate != nil {
		if name := strings.TrimSpace(r.Certificate.Subject.CommonName); name != "" {
			return name
		}
		if serial := strings.TrimSpace(r.Certificate.Subject.SerialNumber); serial != "" {
			return serial
		}
		return "Certificate recipient"
	}
	if r.AuthMeansID != "" {
		return r.AuthMeansID
	}
	if r.Password != "" || r.KDFIterations > 0 {
		return "Password recipient"
	}
	return "Symmetric key recipient"
}
