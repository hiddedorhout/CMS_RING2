# Qualified Ring token library for GO

The Qualified Ring uses tokens to exchange information about positions taken by persons towards informations.
These tokens are based on, and compatible with CMS ([RFC 5652](https://tools.ietf.org/html/rfc5652)).

## Initialize

Make sure openssl is installed and in PATH.

For timestamping on the signatures, environment variables have to be set to find the configuration to make the timestamp tokens and at it to the signerInfo.

* export EXCHANGE_TS_CERT = Timestamping certificate location of the TS Authority (x.509)
* export EXCHANGE_PKEY = Private key of the TS Authority
* export EXCHANGE_TS_DIR = The directory to temporarily store request and place the config file

The configuration file MUST be placed in the $EXCHANGE_TS_DIR location as `ts.cnf` containing the following information:

	# Default section
	[default]
	default_tsa = default_tsa

	[default_tsa]
	home			= $ENV::EXCHANGE_TS_DIR
	serial			= $home/serial
	digests			= sha1
	default_policy		= 0.0.1.2.36
	signer_cert		= $ENV::EXCHANGE_TS_CERT
	signer_key		= $ENV::EXCHANGE_PKEY

For more information see: https://www.openssl.org/docs/manmaster/man1/ts.html


## Variables 

```go
var (
	TmpRequestlocation = os.Getenv("EXCHANGE_TS_DIR") + "/tmpreq.tsq"
	ConfigFileLocation = os.Getenv("EXCHANGE_TS_DIR") + "/ts.cnf"
)	
```

## Build Notifications

### func **InitCMS**

```go
func InitCMS(data []byte) (*SignedData, error)
```

InitCMS takes content as input and returns a SignedData structure

### Type **SignerAttributes**

```go
type SignerAttributes struct {
	SignedAttributes []SignedAttribute
}
```
SignerAttributes are signed attribute values

### Type **SignedAttribute**

```go
type SignedAttribute struct {
	AttrType   asn1.ObjectIdentifier
	AttrValues interface{}
}
```
SignedAttribute is an attribute to be signed by a signer

### func **(SignedData) AddSigner**

```go
func (sd *SignedData) Addsigner(cert x509.Certificate, pkey *rsa.PrivateKey, extraSignedAttributes SignerAttributes, addTimestamp bool)
```

Addsigner adds a signer to an already build CMS token. If `addTimestamp` is TRUE, a timestamp token is added to the unsigned attributes of the signature according to [RFC 3161](https://tools.ietf.org/html/rfc3161). Else, the unsigned attricutes will stay empty

### func **(SignedData) Detach**

```go
func (sd *SignedData) Detach()
```
Detach removes content from the signed data struct to make it a detached signature. This must be called right before BuildCMS()

### func **(SignedData) BuildCMS**

```go
func (sd *SignedData) BuildCMS() ([]byte, error)
```
BuildCMS creates the CMS token

## Parse Notifications

