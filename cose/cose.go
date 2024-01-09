package cose

import (
	"github.com/shogo82148/go-cbor"
)

const (
	// TagNumberCOSESign is the CBOR tag number for COSE_Sign.
	TagNumberCOSESign cbor.TagNumber = 98

	// TagNumberCOSESign1 is the CBOR tag number for COSE_Sign1.
	TagNumberCOSESign1 cbor.TagNumber = 18

	// TagNumberCOSEEncrypt is the CBOR tag number for COSE_Encrypt.
	TagNumberCOSEEncrypt cbor.TagNumber = 96

	// TagNumberCOSEEncrypt0 is the CBOR tag number for COSE_Encrypt0.
	TagNumberCOSEEncrypt0 cbor.TagNumber = 16

	// TagNumberCOSEMac is the CBOR tag number for COSE_Mac.
	TagNumberCOSEMac cbor.TagNumber = 97

	// TagNumberCOSEMac0 is the CBOR tag number for COSE_Mac0.
	TagNumberCOSEMac0 cbor.TagNumber = 17
)
