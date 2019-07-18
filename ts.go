package CMS

import (
	"bytes"
	"os/exec"
)

func createTS(signature []byte) ([]byte, error) {
	buildTSRequest := exec.Command("openssl", "ts", "-query", "-out", TmpRequestlocation)

	buildTSRequest.Stdin = bytes.NewReader(signature)
	var out bytes.Buffer

	buildTSRequest.Stdout = &out

	err := buildTSRequest.Run()
	if err != nil {
		return nil, err
	}

	buildTSResponse := exec.Command("openssl", "ts", "-reply", "-queryfile", TmpRequestlocation, "-config", ConfigFileLocation, "-token_out")

	var tsout bytes.Buffer

	buildTSResponse.Stdout = &tsout

	err2 := buildTSResponse.Run()
	if err2 != nil {
		return nil, err2
	}
	return tsout.Bytes(), nil
}
