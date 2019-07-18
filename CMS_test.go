package CMS

import (
	"encoding/asn1"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"testing"
)

type test struct {
	test string
}

var (
	issOID  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51579, 0, 0, 0, 0}.String()
	audOID  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51579, 0, 0, 0, 1}.String()
	gameOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51579, 0, 0, 0, 3}.String()
	aud     = "nl.clverbaseaa.hidde, nl.clverbase.dorhout"
)

func TestCMS(t *testing.T) {
	p12Location := os.Getenv("EXCHANGE_CA_DIR") + "/p12/hdorhout.p12"
	password := "rugnummer35"

	pkey, cert, err := ParseP12(p12Location, password)
	if err != nil {
		t.Errorf("P12 Error is: %s", err)
	}

	data, err := ioutil.ReadFile("test")
	if err != nil {
		t.Errorf("File Error is: %s", err)
	}

	cms, err := InitCMS(data)
	if err != nil {
		t.Errorf("CMS Error is: %s", err)
	}

	// parse audience
	audSplice := strings.Split(aud, ",")

	Aud := make([]participant, len(audSplice))
	for i, member := range audSplice {
		AudSplice := strings.Split(member, ".")
		AudienceParticipant := participant{
			Country: AudSplice[0],
			TSP:     AudSplice[1],
			ID:      AudSplice[2],
		}
		Aud[i] = AudienceParticipant
	}

	Sic := SignerAttributes{
		SignedAttributes: []SignedAttribute{
			SignedAttribute{
				AttrType: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51579, 0, 0, 0, 0},
				AttrValues: participant{
					Country: "NL",
					TSP:     "Dumbase",
					ID:      "Hidde",
				},
			},
			SignedAttribute{
				AttrType:   asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51579, 0, 0, 0, 1},
				AttrValues: Aud,
			},
		},
	}

	cms.Addsigner(*cert, pkey, Sic, true)

	cms.Detach()

	token, err := cms.BuildCMS()
	if err != nil {
		t.Errorf("CMS Error is: %s", err)
	}

	pToken, err := Parse(token)
	if err != nil {
		t.Errorf("CMS Error is: %s", err)
	}

	signedAttributes := pToken.GetSignedAttributes()
	sI := signedAttributes[pToken.Sd.SignerInfos[0].Sid.Serial]

	// unsignedAttributes := pToken.GetUnSignedAttributes()
	// usI := unsignedAttributes[pToken.sd.SignerInfos[0].Sid.Serial]

	// x, _ := asn1.Marshal(usI[signatureTimeStampToken.String()])

	// tst := pToken.GetTimestampToken(pToken.Sd.SignerInfos[0].Sid.Serial)

	// fmt.Println(base64.StdEncoding.EncodeToString(tst))

	var x []participant

	switch a := sI[audOID].(type) {
	case []byte:
		asn1.Unmarshal(a, &x)
	}

	fmt.Println(x)

}
