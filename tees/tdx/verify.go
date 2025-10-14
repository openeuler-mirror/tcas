package tdx

import (
	"encoding/hex"
	"fmt"
	"tcas/tees"

	abi "github.com/google/go-tdx-guest/abi"
	pb "github.com/google/go-tdx-guest/proto/tdx"
	tdxverify "github.com/google/go-tdx-guest/verify"

	"github.com/beego/beego/v2/core/logs"
)

const TEE_NAME = "tdx"

func init() {
	tees.Register(TEE_NAME, NewVerifier())
	logs.Info("%s verifier registered", TEE_NAME)
}

type Verifier struct{}

func NewVerifier() *Verifier {
	return &Verifier{}
}
func (v *Verifier) VerifyTeeReport(report []byte, parameter interface{}) (tees.VerifyTeeResult, error) {
	if report == nil {
		return nil, fmt.Errorf("report is nil")
	}
	quoteAny, err := abi.QuoteToProto(report)
	if err != nil {
		errMsg := fmt.Errorf("failed to convert to pb.QuoteV4: %v", err)
		logs.Error(errMsg)
		return nil, errMsg
	}
	quote, ok := quoteAny.(*pb.QuoteV4)
	if !ok {
		errMsg := fmt.Errorf("converted result is not a valid *pb.QuoteV4 type")
		logs.Error(errMsg)
		return nil, errMsg
	}
	options := tdxverify.DefaultOptions()
	options.GetCollateral = true
	options.CheckRevocations = true
	if err := tdxverify.TdxQuote(quote, options); err != nil {
		errMsg := fmt.Errorf("quote verification failed: %v", err)
		logs.Error(errMsg)
		return nil, errMsg
	} else {
		logs.Info("quote verification successful")
		verifyTeeResult := v.finalResultQuote(quote)
		return verifyTeeResult, nil
	}
}
func (v *Verifier) byteToHex(tdxdata []byte) string {
	return fmt.Sprintf("%x", tdxdata)
}

func (v *Verifier) finalResultQuote(quote *pb.QuoteV4) tees.VerifyTeeResult {
	verifyTeeResult := make(tees.VerifyTeeResult)
	header := quote.GetHeader()
	body := quote.GetTdQuoteBody()
	verifyTeeResult["tdx_mrsignerseam"] = v.byteToHex(body.GetMrSignerSeam())
	verifyTeeResult["tdx_mrseam"] = v.byteToHex(body.GetMrSeam())
	verifyTeeResult["tdx_mrtd"] = v.byteToHex(body.GetMrTd())
	rtmrs := body.GetRtmrs()
	for i, rtmr := range rtmrs {
		key := fmt.Sprintf("tdx_rtmr%d", i)
		verifyTeeResult[key] = v.byteToHex(rtmr)
	}
	verifyTeeResult["tdx_mrconfigid"] = v.byteToHex(body.GetMrConfigId())
	verifyTeeResult["tdx_mrowner"] = v.byteToHex(body.GetMrOwner())
	verifyTeeResult["tdx_mrownerconfig"] = v.byteToHex(body.GetMrOwnerConfig())
	verifyTeeResult["tdx_report_data"] = v.byteToHex(body.GetReportData())
	verifyTeeResult["tdx_seam_attributes"] = v.byteToHex(body.GetSeamAttributes())
	tdAttributesData := body.GetTdAttributes()
	verifyTeeResult["tdx_td_attributes"] = v.byteToHex(tdAttributesData)
	verifyTeeResult["tdx_td_attributes_debug"] = (tdAttributesData[0] & 0x01) != 0
	verifyTeeResult["tdx_td_attributes_key_locker"] = (tdAttributesData[3] & 0x80) != 0
	verifyTeeResult["tdx_td_attributes_perfmon"] = (tdAttributesData[7] & 0x80) != 0
	verifyTeeResult["tdx_attributes_protection_keys"] = (tdAttributesData[3] & 0x40) != 0
	verifyTeeResult["tdx_attributes_septve_disable"] = (tdAttributesData[3] & 0x10) != 0
	verifyTeeResult["tdx_tee_tcb_svn"] = v.byteToHex(body.GetTeeTcbSvn())
	verifyTeeResult["tdx_xfam"] = v.byteToHex(body.GetXfam())
	verifyTeeResult["tdx_pce_svn"] = v.byteToHex(header.GetPceSvn())
	return verifyTeeResult
}
func (v *Verifier) GetUserData(result tees.VerifyTeeResult) (string, error) {
	if userData, exist := result["tdx_report_data"]; exist {
		if userDataSource, ok := userData.(string); ok {
			decodedData, err := hex.DecodeString(userDataSource)
			if err != nil {
				return "", fmt.Errorf("failed to decode userdata hex string: %v", err)
			}
			return string(decodedData), nil
		}
	}
	return "", fmt.Errorf("userData is not existed, the key is tdx_report_data")
}

func (v *Verifier) GetInitData(result tees.VerifyTeeResult) (string, error) {
	return "", nil
}
