package nvidia

import "C"
import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/beego/beego/v2/client/httplib"
	"github.com/beego/beego/v2/core/logs"
	"github.com/dgrijalva/jwt-go"
	"github.com/goccy/go-json"
	"github.com/lestrrat-go/jwx/v2/cert"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"tcas/tees"
	"tcas/util/convertor"
	"tcas/util/file"
)

func init() {
	tees.Register("nvidia", NewVerifier())
	logs.Info("nvidia verifier registered")
}

const (
	NRASEndpoint    = "https://nras.attestation.nvidia.com"
	MultiAttestURL  = "/v2/attest/gpu"
	SingleAttestURL = "/v1/attest/gpu"
	JWKsURL         = "/.well-known/jwks.json"
	LocalJWKPath    = "./nvidiaJWk.json"
)

type SingleAttestReq struct {
	Nonce string `json:"nonce"`
	Arch  string `json:"arch"`
	NvidiaEvidence
}

type MultiAttestReq struct {
	Nonce     string            `json:"nonce"`
	Arch      string            `json:"arch"`
	Evidences []*NvidiaEvidence `json:"evidences"`
}

type NvidiaEvidence struct {
	Evidence    string `json:"evidence"`
	Certificate string `json:"certificate"`
}

type XNvidiaAttestationDetailedResult struct {
	XNvidiaGpuDriverRimSchemaValidated             bool        `json:"x-nvidia-gpu-driver-rim-schema-validated"`
	XNvidiaGpuVbiosRimCertValidated                bool        `json:"x-nvidia-gpu-vbios-rim-cert-validated"`
	XNvidiaGpuAttestationReportCertChainValidated  bool        `json:"x-nvidia-gpu-attestation-report-cert-chain-validated"`
	XNvidiaGpuDriverRimSchemaFetched               bool        `json:"x-nvidia-gpu-driver-rim-schema-fetched"`
	XNvidiaGpuAttestationReportParsed              bool        `json:"x-nvidia-gpu-attestation-report-parsed"`
	XNvidiaGpuNonceMatch                           bool        `json:"x-nvidia-gpu-nonce-match"`
	XNvidiaGpuVbiosRimSignatureVerified            bool        `json:"x-nvidia-gpu-vbios-rim-signature-verified"`
	XNvidiaGpuDriverRimSignatureVerified           bool        `json:"x-nvidia-gpu-driver-rim-signature-verified"`
	XNvidiaGpuArchCheck                            bool        `json:"x-nvidia-gpu-arch-check"`
	XNvidiaAttestationWarning                      interface{} `json:"x-nvidia-attestation-warning"`
	XNvidiaGpuMeasurementsMatch                    bool        `json:"x-nvidia-gpu-measurements-match"`
	XNvidiaGpuAttestationReportSignatureVerified   bool        `json:"x-nvidia-gpu-attestation-report-signature-verified"`
	XNvidiaGpuVbiosRimSchemaValidated              bool        `json:"x-nvidia-gpu-vbios-rim-schema-validated"`
	XNvidiaGpuDriverRimCertValidated               bool        `json:"x-nvidia-gpu-driver-rim-cert-validated"`
	XNvidiaGpuVbiosRimSchemaFetched                bool        `json:"x-nvidia-gpu-vbios-rim-schema-fetched"`
	XNvidiaGpuVbiosRimMeasurementsAvailable        bool        `json:"x-nvidia-gpu-vbios-rim-measurements-available"`
	XNvidiaGpuDriverRimDriverMeasurementsAvailable bool        `json:"x-nvidia-gpu-driver-rim-driver-measurements-available"`
}
type SignalNvidiaVerifyResult struct {
	Secboot                          bool                              `json:"secboot"`
	XNvidiaGpuManufacturer           string                            `json:"x-nvidia-gpu-manufacturer"`
	XNvidiaAttestationType           string                            `json:"x-nvidia-attestation-type"`
	EatNonce                         string                            `json:"eat_nonce"`
	XNvidiaAttestationDetailedResult *XNvidiaAttestationDetailedResult `json:"x-nvidia-attestation-detailed-result"`
	XNvidiaVer                       string                            `json:"x-nvidia-ver"`
	XNvidiaGpuDriverVersion          string                            `json:"x-nvidia-gpu-driver-version"`
	Dbgstat                          string                            `json:"dbgstat"`
	Hwmodel                          string                            `json:"hwmodel"`
	Oemid                            string                            `json:"oemid"`
	Measres                          string                            `json:"measres"`
	XNvidiaEatVer                    string                            `json:"x-nvidia-eat-ver"`
	Ueid                             string                            `json:"ueid"`
	XNvidiaGpuVbiosVersion           string                            `json:"x-nvidia-gpu-vbios-version"`
	jwt.StandardClaims
}

type MultiNvidiaVerifyResult struct {
	XNvidiaGpuDriverRimSchemaValidated            bool   `json:"x-nvidia-gpu-driver-rim-schema-validated"`
	XNvidiaGpuManufacturer                        string `json:"x-nvidia-gpu-manufacturer"`
	XNvidiaAttestationType                        string `json:"x-nvidia-attestation-type"`
	XNvidiaGpuAttestationReportCertChainValidated bool   `json:"x-nvidia-gpu-attestation-report-cert-chain-validated"`
	EatNonce                                      string `json:"eat_nonce"`
	XNvidiaGpuVbiosRimSignatureVerified           bool   `json:"x-nvidia-gpu-vbios-rim-signature-verified"`
	XNvidiaGpuMeasurementsMatch                   bool   `json:"x-nvidia-gpu-measurements-match"`
	Ueid                                          string `json:"ueid"`
	XNvidiaGpuVbiosRimSchemaFetched               bool   `json:"x-nvidia-gpu-vbios-rim-schema-fetched"`
	XNvidiaGpuVbiosRimCertValidated               bool   `json:"x-nvidia-gpu-vbios-rim-cert-validated"`
	XNvidiaGpuDriverRimSchemaFetched              bool   `json:"x-nvidia-gpu-driver-rim-schema-fetched"`
	XNvidiaGpuAttestationReportParsed             bool   `json:"x-nvidia-gpu-attestation-report-parsed"`
	XNvidiaGpuNonceMatch                          bool   `json:"x-nvidia-gpu-nonce-match"`
	XNvidiaGpuDriverRimSignatureVerified          bool   `json:"x-nvidia-gpu-driver-rim-signature-verified"`
	XNvidiaGpuArchCheck                           bool   `json:"x-nvidia-gpu-arch-check"`
	XNvidiaGpuDriverVersion                       string `json:"x-nvidia-gpu-driver-version"`
	XNvidiaGpuDriverRimMeasurementsAvailable      bool   `json:"x-nvidia-gpu-driver-rim-measurements-available"`
	XNvidiaGpuAttestationReportSignatureVerified  bool   `json:"x-nvidia-gpu-attestation-report-signature-verified"`
	Hwmodel                                       string `json:"hwmodel"`
	Oemid                                         string `json:"oemid"`
	XNvidiaGpuVbiosRimSchemaValidated             bool   `json:"x-nvidia-gpu-vbios-rim-schema-validated"`
	Measres                                       string `json:"measres"`
	XNvidiaGpuDriverRimCertValidated              bool   `json:"x-nvidia-gpu-driver-rim-cert-validated"`
	XNvidiaGpuVbiosVersion                        string `json:"x-nvidia-gpu-vbios-version"`
	XNvidiaGpuVbiosRimMeasurementsAvailable       bool   `json:"x-nvidia-gpu-vbios-rim-measurements-available"`
	jwt.StandardClaims
}

type Parameter struct {
	Certificate string `json:"certificate"`
}
type Verifier struct{}

func NewVerifier() *Verifier {
	return &Verifier{}
}

func (v *Verifier) VerifyTeeReport(report []byte, parameter interface{}) (tees.VerifyTeeResult, error) {
	if report == nil {
		return nil, fmt.Errorf("report is nil")
	}

	p := new(Parameter)
	byteP, err := json.Marshal(parameter)
	if err != nil {
		return nil, fmt.Errorf("marshal parameter failed")
	}
	err = json.Unmarshal(byteP, p)
	if err != nil {
		return nil, fmt.Errorf("unmarshal parameter faield")
	}

	reportByte, err := hex.DecodeString(string(report))
	if err != nil {
		return nil, fmt.Errorf("the format of report must be hex")
	}
	spd := NewSpdmMeasurementRequest(reportByte)

	attestInfo := new(SingleAttestReq)
	attestInfo.Arch = "HOPPER"
	attestInfo.Evidence = base64.StdEncoding.EncodeToString(report)
	attestInfo.Nonce = spd.GetNonce()
	attestInfo.Certificate = p.Certificate

	result, err := v.SignalAttestFromNRAS(attestInfo)
	if err != nil {
		return nil, fmt.Errorf("attest failed, error: %s", err)
	}

	teeResult, err := convertor.AnyToMap(result)
	if err != nil {
		return nil, fmt.Errorf("convert result to map failed, error: %s", err)
	}
	return teeResult, nil
}

func (v *Verifier) GetUserData(result tees.VerifyTeeResult) (string, error) {
	if userData, exist := result["eat_nonce"]; exist {
		return fmt.Sprintf("%s", userData), nil
	} else {
		return "", fmt.Errorf("userData is not existed, the key is eat_nonce")
	}
}

func (v *Verifier) GetInitData(result tees.VerifyTeeResult) (string, error) {
	return "", nil
}

// NVIDIA Remote Attestation Service (NRAS): https://docs.attestation.nvidia.com/
func (v *Verifier) SignalAttestFromNRAS(attestInfo *SingleAttestReq) (*SignalNvidiaVerifyResult, error) {
	client, err := v.newClient("post", SingleAttestURL)
	if err != nil {
		logs.Error("create client failed, error: %v", err)
		return nil, err
	}

	client, err = client.JSONBody(attestInfo)
	if err != nil {
		logs.Error("set request body failed, error: %v", err)
		return nil, err
	}

	resp, err := client.DoRequest()
	if err != nil {
		logs.Error("get response failed, error: %v", err)
		return nil, err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		errMsg := fmt.Sprintf("read response body failed, error: %v", err)
		logs.Error(errMsg)
		return nil, fmt.Errorf(errMsg)
	}

	if resp.StatusCode != 200 {
		errMsg := fmt.Sprintf("do attest failed, error: %s", body)
		logs.Error(errMsg)
		return nil, fmt.Errorf(errMsg)
	}

	var parseRes struct {
		EAT string `json:"eat"`
	}

	err = json.Unmarshal(body, &parseRes)
	if err != nil {
		errMsg := fmt.Sprintf("unmarshal res failed, error: %v", err)
		logs.Error(errMsg)
		return nil, fmt.Errorf(errMsg)
	}

	jwtToken, err := v.VerifyToken(parseRes.EAT)
	if err != nil {
		errMsg := fmt.Sprintf("verify token failed, error: %s", err)
		logs.Error(errMsg)
		return nil, fmt.Errorf(errMsg)
	}

	nvr, err := v.ConvertJwtClaimsToSignalVerifyResult(jwtToken.Claims)
	if err != nil {
		errMsg := fmt.Sprintf("parse jwt claims to result failed, error: %s", err)
		logs.Error(errMsg)
		return nil, fmt.Errorf(errMsg)
	}

	return nvr, nil
}

func (v *Verifier) MultiAttestFromNRAS(attestInfo *MultiAttestReq) (map[string]*MultiNvidiaVerifyResult, error) {
	client, err := v.newClient("post", MultiAttestURL)
	if err != nil {
		logs.Error("create client failed, error: %v", err)
		return nil, err
	}

	client, err = client.JSONBody(attestInfo)
	if err != nil {
		logs.Error("set request body failed, error: %v", err)
		return nil, err
	}

	resp, err := client.DoRequest()
	if err != nil {
		logs.Error("get response failed, error: %v", err)
		return nil, err
	}

	if resp.StatusCode != 200 {
		errMsg := fmt.Sprintf("do attest failed, error: %s", resp)
		logs.Error(errMsg)
		return nil, fmt.Errorf(errMsg)
	}

	var parseRes []interface{}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		errMsg := fmt.Sprintf("read response body failed, error: %v", err)
		logs.Error(errMsg)
		return nil, fmt.Errorf(errMsg)
	}
	err = json.Unmarshal(body, &parseRes)
	if err != nil {
		errMsg := fmt.Sprintf("unmarshal res failed, error: %v", err)
		logs.Debug("res: %s", body)
		logs.Error(errMsg)
		return nil, fmt.Errorf(errMsg)
	}

	if len(parseRes) != 2 {
		errMsg := fmt.Sprintf("res size error")
		logs.Error(errMsg)
		return nil, fmt.Errorf(errMsg)
	}

	summaryValue, exist := parseRes[0].([]interface{})
	if !exist {
		errMsg := fmt.Sprintf("could not parse res")
		logs.Error(errMsg)
		return nil, fmt.Errorf(errMsg)
	}

	if len(summaryValue) != 2 {
		return nil, fmt.Errorf("summary value size error")
	}
	summaryToken, exist := summaryValue[1].(string)
	if !exist {
		return nil, fmt.Errorf("summary token is not exist")
	}
	fmt.Println(summaryToken)

	verifiedSummaryJwt, err := v.VerifyToken(summaryToken)
	if err != nil {
		return nil, fmt.Errorf("verify token failed, error:%s", err)
	}
	fmt.Println(verifiedSummaryJwt.Claims)

	summaryJwtClaims, ok := verifiedSummaryJwt.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("convert jwt claims to map failed")
	}

	submods, exist := summaryJwtClaims["submods"]
	if !exist {
		return nil, fmt.Errorf("summary jwt token miss submods claims")
	}

	mapSubmods, ok := submods.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("convert submods to map failed")
	}

	gpusToken, exist := parseRes[1].(map[string]interface{})
	if !exist {
		return nil, fmt.Errorf("the echo token of gpus do not exist")
	}

	if len(gpusToken) != len(attestInfo.Evidences) {
		return nil, fmt.Errorf("miss token")
	}

	results := make(map[string]*MultiNvidiaVerifyResult)
	for k, t := range gpusToken {
		if tokenstring, exist := t.(string); !exist {
			return nil, fmt.Errorf("the %s's token value is not string", k)
		} else {
			tsha256 := sha256.Sum256([]byte(tokenstring))
			tsha256Hex := hex.EncodeToString(tsha256[:])
			logs.Debug("the sha256 of %s token is %s ", k, tsha256Hex)
			gpuSubmod, exist := mapSubmods[k]
			if !exist {
				return nil, fmt.Errorf("the gpuSubmod of %s miss", k)
			}

			logs.Debug(gpuSubmod)
			sliceGpuSubmod, ok := gpuSubmod.([]interface{})
			if !ok {
				return nil, fmt.Errorf("the gpusubmod is not slice")
			}

			if len(sliceGpuSubmod) < 2 {
				return nil, fmt.Errorf("the size of gpuDigest must > 2")
			}
			sliceGpuDigest, ok := sliceGpuSubmod[1].([]interface{})
			if !ok {
				return nil, fmt.Errorf("the gpu disgest is not slice")
			}

			if len(sliceGpuDigest) < 2 {
				return nil, fmt.Errorf("the size of gpu digest must > 2")
			}

			logs.Debug(sliceGpuDigest)
			expectSha256, ok := sliceGpuDigest[1].(string)
			if !ok {
				return nil, fmt.Errorf("expectSha256 must be string")
			}

			if tsha256Hex != expectSha256 {
				return nil, fmt.Errorf("token's sha256 does not meach the value in summary")
			}

			JWT, err := v.VerifyToken(tokenstring)
			if err != nil {
				return nil, fmt.Errorf("the token of %s is not vailed, error: %s", k, err)
			}

			//nvr := new(MultiNvidiaVerifyResult)
			nvr, err := v.ConvertJwtClaimsToStruct(JWT.Claims)
			if err != nil {
				return nil, fmt.Errorf("the claims in jwt is not correct")
			}
			results[k] = nvr
		}
	}

	return results, nil
}

func (v *Verifier) ConvertJwtClaimsToStruct(claims jwt.Claims) (*MultiNvidiaVerifyResult, error) {
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return nil, err
	}
	var nvr MultiNvidiaVerifyResult
	err = json.Unmarshal(claimsJSON, &nvr)
	if err != nil {
		return nil, err
	}

	return &nvr, nil
}

func (v *Verifier) ConvertJwtClaimsToSignalVerifyResult(claims jwt.Claims) (*SignalNvidiaVerifyResult, error) {
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return nil, err
	}

	var nvr SignalNvidiaVerifyResult
	err = json.Unmarshal(claimsJSON, &nvr)
	if err != nil {
		return nil, err
	}

	nvr.StandardClaims = jwt.StandardClaims{}
	return &nvr, nil
}

func (v *Verifier) newClient(method string, inputUrl string) (*httplib.BeegoHTTPRequest, error) {
	var client *httplib.BeegoHTTPRequest
	me := strings.ToUpper(method)
	client = httplib.NewBeegoRequest(NRASEndpoint+inputUrl, me)
	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		RootCAs: rootCAs,
	}

	client.SetTLSClientConfig(tlsConfig)

	proxy := os.Getenv("HTTPS_PROXY")
	if proxy != "" {
		client.SetProxy(func(req *http.Request) (*url.URL, error) {
			u, _ := url.ParseRequestURI(proxy)
			return u, nil
		})
	}

	return client, nil
}

func (v *Verifier) VerifyToken(tokenString string) (*jwt.Token, error) {
	parsedToken, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {

		var kid string
		keyValue, exists := token.Header["kid"]
		if !exists {
			return nil, fmt.Errorf("kid field missing in token header")
		} else {
			var ok bool
			kid, ok = keyValue.(string)
			if !ok {
				return nil, fmt.Errorf("kid field in jwt header is not a valid string: %v", kid)
			}
		}

		JWK, err := v.GetTokenVerifyCerts(kid)
		if err != nil {
			return nil, fmt.Errorf("get verify certs failed, error: %s", err)
		}
		NRASCerts := JWK.X509CertChain()

		root := x509.NewCertPool()
		var leafCert *x509.Certificate
		for i := 0; i < NRASCerts.Len(); i++ {
			tmpcert, exists := NRASCerts.Get(i)
			if !exists {
				return nil, fmt.Errorf("index %d of cert not exists", i)
			}
			cer, err := cert.Parse(tmpcert)
			if err != nil {
				return nil, fmt.Errorf("failed to parse x509 certificate[%d]: %v", i, err)
			}

			if cer.IsCA && cer.BasicConstraintsValid {
				root.AddCert(cer)
			} else {
				leafCert = cer
			}
		}

		// Verify the Leaf certificate against the CA
		opts := x509.VerifyOptions{
			Roots: root,
		}

		if _, err := leafCert.Verify(opts); err != nil {
			return nil, fmt.Errorf("failed to verify cert chain: %v", err)
		}

		// get the public key from JWK
		var pubKey ecdsa.PublicKey
		err = JWK.Raw(&pubKey)
		if err != nil {
			return nil, fmt.Errorf("failed to extract public Key from certificate: %s", err)
		}
		return &pubKey, nil
	})
	if err != nil {
		errMsg := fmt.Sprintf("parse token failed, error: %s", err)
		logs.Error(errMsg)
		return nil, fmt.Errorf(errMsg)
	}

	return parsedToken, nil
}

func (v *Verifier) GetTokenVerifyCerts(kid string) (jwk.Key, error) {
	// find jwk in local first
	if file.IsFile(LocalJWKPath) {
		jwks, err := os.ReadFile(LocalJWKPath)
		if err == nil {
			jwkSet, err := jwk.Parse(jwks)
			if err == nil {
				jwkKey, found := jwkSet.LookupKeyID(kid)
				if !found {
					logs.Info("not find jwk in local failed, try to download on line")
				} else {
					return jwkKey, nil
				}
			}
		}
	}

	client, err := v.newClient("get", JWKsURL)
	if err != nil {
		return nil, err
	}

	res, err := client.DoRequest()
	if err != nil {
		errMsg := fmt.Sprintf("do request to get token failed, error: %s", err)
		logs.Error(errMsg)
		return nil, err
	}

	jwks, err := io.ReadAll(res.Body)
	if err != nil {
		errMsg := fmt.Sprintf("read body failed, error: %s", err)
		logs.Error(errMsg)
		return nil, fmt.Errorf(errMsg)
	}
	err = os.WriteFile(LocalJWKPath, jwks, os.ModePerm)
	if err != nil {
		logs.Warning("save jwks in %s failed, error: %s", LocalJWKPath, err)
	}

	// Unmarshal the JWKS
	jwkSet, err := jwk.Parse(jwks)
	if err != nil {
		return nil, fmt.Errorf("unable to unmarshal response into a JWT Key Set: %s", err)
	}

	jwkKey, found := jwkSet.LookupKeyID(kid)
	if !found {
		return nil, fmt.Errorf("could not find Key matching the key id")
	}

	return jwkKey, nil
}
