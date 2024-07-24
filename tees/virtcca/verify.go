package virtcca

/*
#cgo LDFLAGS: -lvccaverifier -lt_cose -L/usr/lib/x86_64-linux-gnu/ -lcrypto -lqcbor -lm
#include "token_validate.h"
#include "token_parse.h"
*/
import "C"
import (
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/beego/beego/v2/core/logs"
	"github.com/google/uuid"
	"os"
	"path"
	"tcas/tees"
	"unsafe"
)

func init() {
	tees.Register("virtcca", NewVerifier())
	logs.Info("virtcca verifier registered")
}

type Verifier struct{}

type CCAToken struct {
	CVMEnvelop C.cose_sign1_envelop_t
	CVMCose    C.qbuf_t
	CVMToken   C.cvm_claims_t
}

type CVMClaims struct {
	Challenge        string `json:"virtcca_challenge"`
	RPV              string `json:"virtcca_rpv"`
	RIM              string `json:"virtcca_rim"`
	REM0             string `json:"virtcca_rem0"`
	REM1             string `json:"virtcca_rem1"`
	REM2             string `json:"virtcca_rem2"`
	REM3             string `json:"virtcca_rem3"`
	HashAlgoId       string `json:"virtcca_hash_algo_id"`
	PubKey           string `json:"virtcca_pub_key"`
	PubKeyHashAlgoId string `json:"virtcca_pub_key_hash_algo_id"`
}

type AikCert struct {
	X5c string `json:"x5c"`
}

func NewVerifier() *Verifier {
	return &Verifier{}
}

func (v *Verifier) VerifyTeeReport(report []byte, parameter interface{}) (tees.VerifyTeeResult, error) {
	if report == nil {
		return nil, fmt.Errorf("report is nil")
	}

	//the parameter is the aik cert of virtcca
	aikCertSavePath, err := v.SaveAikCert(parameter)
	if err != nil {
		return nil, fmt.Errorf("parse the aik cert from parameter failed, error: %s", err)
	}
	defer os.RemoveAll(aikCertSavePath)

	// Convert Go byte slice to C unsigned char pointer
	cToken := (*C.uchar)(unsafe.Pointer(&report[0]))
	// Convert Go slice length to C size_t
	cTokenLen := C.size_t(len(report))
	// Call the C function of verify full token
	cAikPath := C.CString(aikCertSavePath)

	result := C.verify_full_token(cToken, cTokenLen, cAikPath)
	if result != 0 {
		return nil, fmt.Errorf("verify full token failed, error: return code %d", int(result))
	}

	token := CCAToken{}
	status := C.parse_cca_attestation_token(
		(*C.cca_token_t)(unsafe.Pointer(&token)),
		cToken,
		cTokenLen)

	if status != 0 {
		return nil, fmt.Errorf("parse cca attestation token failed, error: return code %d", int(status))
	}

	cvmClaims, err := v.GetCVMClaimsFromCCAToken(&token)
	if err != nil {
		return nil, fmt.Errorf("get cvm claims from cca token failed, error:%s", err)
	}
	claims, err := json.Marshal(cvmClaims)
	if err != nil {
		return nil, fmt.Errorf("marshal cvm Claims failed, error: %s", err.Error())
	}
	logs.Debug("attestation result is %s", claims)

	ar := tees.VerifyTeeResult{}
	if err := json.Unmarshal(claims, &ar); err != nil {
		return nil, fmt.Errorf("unmarshal cvm Claims failed, error: %s", err.Error())
	}
	return ar, nil
}

func (v *Verifier) GetUserData(result tees.VerifyTeeResult) (string, error) {
	if userData, exist := result["virtcca_challenge"]; exist {
		return fmt.Sprintf("%s", userData), nil
	} else {
		return "", fmt.Errorf("userData is not existed, the key is virtcca_challenge")
	}
}

func (v *Verifier) GetInitData(result tees.VerifyTeeResult) (string, error) {
	if initData, exist := result["virtcca_rpv"]; exist {
		return fmt.Sprintf("%s", initData), nil
	} else {
		return "", fmt.Errorf("initData is not existed, the key is virtcca_rpv")
	}
}

func (v *Verifier) GetCVMClaimsFromCCAToken(ccaToken *CCAToken) (*CVMClaims, error) {
	if ccaToken == nil {
		return nil, fmt.Errorf("ccaToken is nil")
	}
	cvmClaims := new(CVMClaims)
	cvmClaimsPtr := (*C.cvm_claims_t)(unsafe.Pointer(&ccaToken.CVMToken))
	cvmClaims.Challenge = hex.EncodeToString([]byte(C.GoStringN((*C.char)(cvmClaimsPtr.challenge.ptr), C.int(cvmClaimsPtr.challenge.len))))
	cvmClaims.RPV = hex.EncodeToString([]byte(C.GoStringN((*C.char)(cvmClaimsPtr.rpv.ptr), C.int(cvmClaimsPtr.rpv.len))))
	cvmClaims.RIM = hex.EncodeToString([]byte(C.GoStringN((*C.char)(cvmClaimsPtr.rim.ptr), C.int(cvmClaimsPtr.rim.len))))
	cvmClaims.REM0 = hex.EncodeToString([]byte(C.GoStringN((*C.char)(cvmClaimsPtr.rem[0].ptr), C.int(cvmClaimsPtr.rem[0].len))))
	cvmClaims.REM1 = hex.EncodeToString([]byte(C.GoStringN((*C.char)(cvmClaimsPtr.rem[1].ptr), C.int(cvmClaimsPtr.rem[1].len))))
	cvmClaims.REM2 = hex.EncodeToString([]byte(C.GoStringN((*C.char)(cvmClaimsPtr.rem[2].ptr), C.int(cvmClaimsPtr.rem[2].len))))
	cvmClaims.REM3 = hex.EncodeToString([]byte(C.GoStringN((*C.char)(cvmClaimsPtr.rem[3].ptr), C.int(cvmClaimsPtr.rem[3].len))))
	cvmClaims.HashAlgoId = C.GoStringN((*C.char)(cvmClaimsPtr.hash_algo_id.ptr), C.int(cvmClaimsPtr.hash_algo_id.len))
	cvmClaims.PubKey = hex.EncodeToString([]byte(C.GoStringN((*C.char)(cvmClaimsPtr.pub_key.ptr), C.int(cvmClaimsPtr.pub_key.len))))
	cvmClaims.PubKeyHashAlgoId = C.GoStringN((*C.char)(cvmClaimsPtr.pub_key_hash_algo_id.ptr), C.int(cvmClaimsPtr.pub_key_hash_algo_id.len))

	return cvmClaims, nil
}

func (v *Verifier) SaveAikCert(parameter interface{}) (savePath string, err error) {
	aik := new(AikCert)
	byteP, err := json.Marshal(parameter)
	if err != nil {
		return "", fmt.Errorf("marshal aik parameter failed")
	}
	err = json.Unmarshal(byteP, aik)
	if err != nil {
		return "", fmt.Errorf("unmarshal aik parameter faield")
	}
	fmt.Println(aik.X5c)
	certDER, err := base64.StdEncoding.DecodeString(aik.X5c)
	if err != nil {
		return "", fmt.Errorf("failed to decode certificate:", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return "", fmt.Errorf("failed to parse certificate:", err)
	}

	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	aikCertSavePath := path.Join("/tmp", fmt.Sprintf("%s-aik-cert.pem", uuid.NewString()))
	// write the PEM certificate to a file
	f, err := os.Create(aikCertSavePath)
	if err != nil {
		return "", fmt.Errorf("create aik save file failed, error: %s", err)
	}
	defer f.Close()
	err = pem.Encode(f, pemBlock)
	if err != nil {
		return "", fmt.Errorf("save aik cert to %s failed, error:%s", aikCertSavePath, err)
	}
	return aikCertSavePath, nil
}
