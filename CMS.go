package CMS

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"math/big"
	"os"
	"time"

	"golang.org/x/crypto/pkcs12"
)

var (
	signedDataOID                   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	dataOID                         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	digestAlgorithmSHA256           = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	digestAlgorithmSHA256WithRSAOID = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	attributeContentTypeOID         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	attributeMessageDigestOID       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	signingTimeOID                  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	signatureTimeStampToken         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 14}
)

var (
	TmpRequestlocation = os.Getenv("EXCHANGE_TS_DIR") + "/tmpreq.tsq"
	ConfigFileLocation = os.Getenv("EXCHANGE_TS_DIR") + "/ts.cnf"
)

type contentInfo struct {
	EContentType asn1.ObjectIdentifier
	Content      asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type issuerSerial struct {
	Issuer asn1.RawValue
	Serial *big.Int
}

type signerIdentifier struct {
	IssuerSerial issuerSerial
}

type attribute struct {
	AttrType   asn1.ObjectIdentifier
	AttrValues asn1.RawValue `asn1:"set"`
}

type signedAttribute struct {
	attributes []attribute
}

type signerInfos struct {
	Version            int `asn1:"default:1"`
	Sid                issuerSerial
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignedAttributes   []attribute `asn1:"optional,tag:0"`
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
	UnSignedAttributes []attribute `asn1:"optional,tag:1"`
}

// CMS is the structure of the signed data
type CMS struct {
	Version          int                        `asn1:"default:1"`
	DigestAlgorithm  []pkix.AlgorithmIdentifier `asn1:"set"`
	EncapContentInfo contentInfo
	SignerInfos      []signerInfos `asn1:"set"`
}

type signedData struct {
	Version          int                        `asn1:"default:1"`
	DigestAlgorithm  []pkix.AlgorithmIdentifier `asn1:"set"`
	EncapContentInfo contentInfo
	SignerInfos      []signerInfos `asn1:"set"`
}

// SignedData is an opaque struct for building the CMS
type SignedData struct {
	Sd            signedData
	certs         []x509.Certificate
	messageDigest []byte
}

// SignedCMS is an opaque struct for signing and handling an already build CMS
type SignedCMS struct {
	Sd            CMS
	Certs         []x509.Certificate
	MessageDigest []byte
}

//SignedAttribute is an attribute signed by a signer
type SignedAttribute struct {
	AttrType   asn1.ObjectIdentifier
	AttrValues interface{}
}

// SignerAttributes are signed attribute values
type SignerAttributes struct {
	SignedAttributes []SignedAttribute
}

func sign(attrs []attribute, pkey *rsa.PrivateKey, hash crypto.Hash) ([]byte, error) {

	type signedAttrs struct {
		Attrs []attribute `asn1:"set"`
	}
	encodedAttrs, err := asn1.Marshal(signedAttrs{Attrs: attrs})
	if err != nil {
		return nil, err
	}

	var raw asn1.RawValue

	asn1.Unmarshal(encodedAttrs, &raw)

	h := hash.New()
	h.Write(raw.Bytes)
	hashed := h.Sum(nil)

	signature, err := rsa.SignPKCS1v15(rand.Reader, pkey, crypto.SHA256, hashed)
	if err != nil {
		return nil, err
	}
	return signature, nil
}

// InitCMS takes the ASN.1 marshalled content as input and returns a SignedData structure
func InitCMS(data []byte) (*SignedData, error) {
	content, err := asn1.Marshal(data)
	if err != nil {
		return nil, err
	}

	var sd signedData

	sd.Version = 1
	da := pkix.AlgorithmIdentifier{Algorithm: digestAlgorithmSHA256}

	sd.DigestAlgorithm = []pkix.AlgorithmIdentifier{da}

	sd.EncapContentInfo = contentInfo{
		EContentType: dataOID,
		Content: asn1.RawValue{
			Class:      2,
			Tag:        0,
			Bytes:      content,
			IsCompound: true,
		},
	}

	hash := sha256.New()
	hash.Write(data)
	messageDigest := hash.Sum(nil)

	SD := &SignedData{
		Sd:            sd,
		messageDigest: messageDigest,
	}

	return SD, nil
}

func (sa *SignerAttributes) marshallAttrs() ([]attribute, error) {
	attrList := make([]attribute, len(sa.SignedAttributes))

	for i, v := range sa.SignedAttributes {
		marshalledValue, err := asn1.Marshal(v.AttrValues)
		if err != nil {
			return nil, err
		}
		attr := attribute{
			AttrType: v.AttrType,
			AttrValues: asn1.RawValue{
				Tag:        17,
				IsCompound: true,
				Bytes:      marshalledValue,
			},
		}

		attrList[i] = attr
	}
	return attrList, nil
}

// Addsigner adds a signer to sign the content
func (sd *SignedData) Addsigner(cert x509.Certificate, pkey *rsa.PrivateKey, extraSignedAttributes SignerAttributes, addTimestamp bool) error {

	var attr SignerAttributes
	attr.SignedAttributes = append(attr.SignedAttributes, SignedAttribute{
		AttrType:   attributeContentTypeOID,
		AttrValues: sd.Sd.EncapContentInfo.EContentType,
	})
	attr.SignedAttributes = append(attr.SignedAttributes, SignedAttribute{
		AttrType:   attributeMessageDigestOID,
		AttrValues: sd.messageDigest,
	})
	attr.SignedAttributes = append(attr.SignedAttributes, SignedAttribute{
		AttrType:   signingTimeOID,
		AttrValues: time.Now(),
	})

	for _, signedAttr := range extraSignedAttributes.SignedAttributes {
		attr.SignedAttributes = append(attr.SignedAttributes, SignedAttribute{
			AttrType:   signedAttr.AttrType,
			AttrValues: signedAttr.AttrValues,
		})
	}

	finalAttrs, _ := attr.marshallAttrs()

	signature, err := sign(finalAttrs, pkey, crypto.SHA256)
	if err != nil {
		return err
	}

	var unsigendAttr SignerAttributes

	if addTimestamp {

		timeStampToken, err := createTS(signature)
		if err != nil {
			return err
		}

		unsigendAttr.SignedAttributes = append(unsigendAttr.SignedAttributes, SignedAttribute{
			AttrType:   signatureTimeStampToken,
			AttrValues: timeStampToken,
		})

	}

	finalUnsignedAttrs, _ := unsigendAttr.marshallAttrs()

	si := signerInfos{
		Version: 1,
		Sid: issuerSerial{
			Issuer: asn1.RawValue{FullBytes: cert.RawIssuer},
			Serial: cert.SerialNumber,
		},
		SignedAttributes:   finalAttrs,
		DigestAlgorithm:    pkix.AlgorithmIdentifier{Algorithm: digestAlgorithmSHA256},
		SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: digestAlgorithmSHA256WithRSAOID},
		Signature:          signature,
		UnSignedAttributes: finalUnsignedAttrs,
	}

	sd.certs = append(sd.certs, cert)
	sd.Sd.SignerInfos = append(sd.Sd.SignerInfos, si)

	return nil
}

// Detach removes content from the signed data struct to make it a detached signature.
// This must be called right before BuildCMS()
func (sd *SignedData) Detach() {
	sd.Sd.EncapContentInfo = contentInfo{EContentType: signedDataOID}
}

//BuildCMS creates the CMS token
func (sd *SignedData) BuildCMS() ([]byte, error) {

	signedData, err := asn1.Marshal(sd.Sd)
	if err != nil {
		return nil, err
	}

	cms := contentInfo{
		EContentType: signedDataOID,
		Content: asn1.RawValue{
			Class:      2,
			Tag:        0,
			Bytes:      signedData,
			IsCompound: true,
		},
	}
	return asn1.Marshal(cms)
}

// Parse parses a CMS message for further processing
func Parse(data []byte) (cms *SignedData, err error) {
	var info contentInfo

	der, err := ber2der(data)
	if err != nil {
		return nil, err
	}

	asn1.Unmarshal(der, &info)

	var sd CMS
	asn1.Unmarshal(info.Content.Bytes, &sd)

	signedData, err := cmsToSignedData(&sd)
	if err != nil {
		return nil, err
	}

	return signedData, nil

}

// CMStoSignedData is an util to convert a CMS type to a SignedDate type for further processing
func cmsToSignedData(cms *CMS) (*SignedData, error) {

	sd := signedData{
		Version:          cms.Version,
		DigestAlgorithm:  cms.DigestAlgorithm,
		EncapContentInfo: cms.EncapContentInfo,
		SignerInfos:      cms.SignerInfos,
	}

	return &SignedData{
		Sd: sd,
	}, nil
}

type participant struct {
	Country string
	TSP     string
	ID      string
}

// GetSignedAttributes returns a map of the signed attributes by the certificate the belong to
func (sd *SignedData) GetSignedAttributes() map[*big.Int]map[string]interface{} {

	siList := make(map[*big.Int]map[string]interface{})
	for _, si := range sd.Sd.SignerInfos {
		attrList := make(map[string]interface{})
		for _, attr := range si.SignedAttributes {

			var val asn1.RawValue
			asn1.Unmarshal(attr.AttrValues.Bytes, &val)

			var result participant
			asn1.Unmarshal(val.FullBytes, &result)

			if result == (participant{}) {
				var altResult interface{}
				asn1.Unmarshal(val.FullBytes, &altResult)

				if altResult == nil {
					attrList[attr.AttrType.String()] = val.FullBytes
				} else {
					attrList[attr.AttrType.String()] = altResult
				}
			} else {
				attrList[attr.AttrType.String()] = result
			}

		}
		siList[si.Sid.Serial] = attrList
	}
	return siList
}

// GetUnSignedAttributes returns a map of the signed attributes by the certificate the belong to
func (sd *SignedData) GetUnSignedAttributes() map[*big.Int]map[string]interface{} {

	siList := make(map[*big.Int]map[string]interface{})

	for _, si := range sd.Sd.SignerInfos {
		// attrList := make([]SignedAttribute, len(si.UnSignedAttributes))
		attrList := make(map[string]interface{})
		for _, attr := range si.UnSignedAttributes {

			var val asn1.RawValue
			asn1.Unmarshal(attr.AttrValues.Bytes, &val)

			var result interface{}
			asn1.Unmarshal(val.FullBytes, &result)

			attrList[attr.AttrType.String()] = result
		}
		siList[si.Sid.Serial] = attrList
	}
	return siList
}

// GetTimestampToken returns the timestamp token belonging to a signerinfo of a particular certificate serial
func (sd *SignedData) GetTimestampToken(certificateSerial *big.Int) []byte {

	siList := make(map[*big.Int]map[string][]byte)

	for _, si := range sd.Sd.SignerInfos {

		attrList := make(map[string][]byte)
		for _, attr := range si.UnSignedAttributes {

			var val asn1.RawValue
			asn1.Unmarshal(attr.AttrValues.Bytes, &val)

			attrList[attr.AttrType.String()] = val.FullBytes
		}
		siList[si.Sid.Serial] = attrList
	}
	uSI := siList[certificateSerial]
	return uSI[signatureTimeStampToken.String()]
}

// ParseP12 is utility to parse a p12 certificate
func ParseP12(base64P12 string, passPtr string) (privateKey *rsa.PrivateKey, certificate *x509.Certificate, err error) {

	p12, err := base64.StdEncoding.DecodeString(base64P12)
	if err != nil {
		return nil, nil, err
	}

	key, cert, err := pkcs12.Decode(p12, passPtr)
	if err != nil {
		return nil, nil, errors.New("parseP12: Could not decode p12 certificate, check password")
	}

	var prKey *rsa.PrivateKey

	switch k := key.(type) {
	case *rsa.PrivateKey:
		prKey = k
	default:
		return nil, nil, errors.New("could not get private key")
	}

	return prKey, cert, nil
}
