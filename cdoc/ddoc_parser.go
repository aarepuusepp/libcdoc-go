package cdoc

import (
	"encoding/base64"
	"encoding/xml"

	"github.com/aarepuusepp/libcdoc-go/v2/internal"
)

// DDOCSignedDoc represents the root element of a DDOC structure
type DDOCSignedDoc struct {
	XMLName   xml.Name      `xml:"SignedDoc"`
	Format    string        `xml:"format,attr"`
	Version   string        `xml:"version,attr"`
	DataFiles []DDOCDataFile `xml:"DataFile"`
}

// DDOCDataFile represents a file in DDOC structure
type DDOCDataFile struct {
	Filename    string `xml:"Filename,attr"`
	ContentType string `xml:"ContentType,attr"`
	Id          string `xml:"Id,attr"`
	MimeType    string `xml:"MimeType,attr"`
	Size        string `xml:"Size,attr"`
	Base64Value string `xml:",chardata"` // Base64Value is the character data content of DataFile element
}

// ParseDDOC parses a DDOC XML structure and extracts all files
func ParseDDOC(data []byte) ([]DecryptedFile, error) {
	var signedDoc DDOCSignedDoc
	if err := xml.Unmarshal(data, &signedDoc); err != nil {
		return nil, internal.NewDecryptionError("failed to parse DDOC XML", err)
	}

	var files []DecryptedFile
	for _, df := range signedDoc.DataFiles {
		content, err := base64.StdEncoding.DecodeString(df.Base64Value)
		if err != nil {
			return nil, internal.NewDecryptionError("failed to decode base64 content for file: "+df.Filename, err)
		}

		files = append(files, DecryptedFile{
			Name:    df.Filename,
			Content: content,
		})
	}

	if len(files) == 0 {
		return nil, internal.NewDecryptionError("DDOC structure contains no data files", nil)
	}

	return files, nil
}

