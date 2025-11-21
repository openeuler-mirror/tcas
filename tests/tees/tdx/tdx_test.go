package tests

import (
	"os"
	"tcas/tees"
	_ "tcas/tees/tdx"
	"testing"
)

const TeeType = "tdx"

type ExceptedTDAttributes struct {
	Debug          bool `json:"debug"`
	KeyLocker      bool `json:"key_locker"`
	Perfmon        bool `json:"perfmon"`
	ProtectionKeys bool `json:"protection_keys"`
	SeptveDisable  bool `json:"septve_disable"`
}

type ExceptedTdxData struct {
	Quote        ExceptedQuote        `json:"quote"`
	TDAttributes ExceptedTDAttributes `json:"td_attributes"`
}

// Existing Quote structs
type ExceptedQuoteBody struct {
	MRConfigID     string `json:"mr_config_id"`
	MROwner        string `json:"mr_owner"`
	MROwnerConfig  string `json:"mr_owner_config"`
	MRSeam         string `json:"mr_seam"`
	MRTD           string `json:"mr_td"`
	MRSignerSeam   string `json:"mrsigner_seam"`
	ReportData     string `json:"report_data"`
	RTMR0          string `json:"rtmr_0"`
	RTMR1          string `json:"rtmr_1"`
	RTMR2          string `json:"rtmr_2"`
	RTMR3          string `json:"rtmr_3"`
	SeamAttributes string `json:"seam_attributes"`
	TCB_SVN        string `json:"tcb_svn"`
	TDAttributes   string `json:"td_attributes"`
	XFAM           string `json:"xfam"`
}

type ExceptedQuote struct {
	Body ExceptedQuoteBody `json:"body"`
}

func TestVerifyWorkflow(t *testing.T) {
	var verifyTcasResult tees.VerifyTeeResult
	var expectTdxData = &ExceptedTdxData{
		TDAttributes: ExceptedTDAttributes{
			Debug:          false,
			KeyLocker:      false,
			Perfmon:        false,
			ProtectionKeys: false,
			SeptveDisable:  true,
		},
		Quote: ExceptedQuote{
			Body: ExceptedQuoteBody{
				MRConfigID:     "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
				MROwner:        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
				MROwnerConfig:  "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
				MRSeam:         "49b66faa451d19ebbdbe89371b8daf2b65aa3984ec90110343e9e2eec116af08850fa20e3b1aa9a874d77a65380ee7e6",
				MRTD:           "684a473d0d3ecb03694b6c18c647e31ce5f7f8dfe5b2122d6d4e96896d54e13dedd7b73ced5c82087aa2f29b39d0f73f",
				MRSignerSeam:   "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
				ReportData:     "63636564366661373132623962343832326433386338333036613162366463303566346635663030643762373733346161373837616132376138336266666136",
				RTMR0:          "0c8e32a161b16cf82daa54974f02d97aa60deb02eb66977b8efd325eb87a0636803b9243218ab33f76c7981c4fb67417",
				RTMR1:          "1d761537eae473fae3f447011e25ae562c076bc6efba4364f3deaa922c7569025887b373c39fadcce583d046e1f02878",
				RTMR2:          "2eae3dd9c0b5ff0d9a6fde48d8d6b0fa7bfe5f48fa58d37458dd9a58258dc454d274da03b82da8c7fc1e1d7cd7aee2c4",
				RTMR3:          "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
				SeamAttributes: "0000000000000000",
				TCB_SVN:        "07010300000000000000000000000000",
				TDAttributes:   "0000001000000000",
				XFAM:           "e702060000000000",
			},
		},
	}

	t.Run("VerifyReportByTcas", func(t *testing.T) {
		data, err := os.ReadFile("tdx_quote.dat")
		if err != nil {
			t.Fatal("Read tdx_quote.dat failed:", err)
		}
		var parameter interface{}
		verifyTcasResult, err = tees.Verifiers[TeeType].VerifyTeeReport(data, parameter)
		if err != nil {
			t.Fatal("Verify TDX report failed:", err)
		}
		t.Log("Get tcas token success!", verifyTcasResult)
	})

	t.Run("Compare[mrsignerseam]", func(t *testing.T) {
		tcasValue, ok := verifyTcasResult["tdx_mrsignerseam"].(string)
		if !ok {
			t.Fatal("Failed to get tcas tdx_mrsignerseam as string")
		}
		expectedValue := expectTdxData.Quote.Body.MRSignerSeam
		if tcasValue != expectedValue {
			t.Fatalf("This field [MRSignerSeam] does not match the expected value; the expected value is [%s], but the actual value is [%s].", expectedValue, tcasValue)
		}
	})

	t.Run("Compare[mrseam]", func(t *testing.T) {
		tcasValue, ok := verifyTcasResult["tdx_mrseam"].(string)
		if !ok {
			t.Fatal("Failed to get tcas tdx_mrseam as string")
		}
		expectedValue := expectTdxData.Quote.Body.MRSeam
		if tcasValue != expectedValue {
			t.Fatalf("This field [mrseam] does not match the expected value; the expected value is [%s], but the actual value is [%s].", expectedValue, tcasValue)
		}
	})

	t.Run("Compare[mrtd]", func(t *testing.T) {
		tcasValue, ok := verifyTcasResult["tdx_mrtd"].(string)
		if !ok {
			t.Fatal("Failed to get tcas tdx_mrtd as string")
		}
		expectedValue := expectTdxData.Quote.Body.MRTD
		if tcasValue != expectedValue {
			t.Fatalf("This field [mrtd] does not match the expected value; the expected value is [%s], but the actual value is [%s].", expectedValue, tcasValue)
		}
	})

	t.Run("Compare[rtmr0]", func(t *testing.T) {
		tcasValue, ok := verifyTcasResult["tdx_rtmr0"].(string)
		if !ok {
			t.Fatal("Failed to get tcas tdx_rtmr0 as string")
		}
		expectedValue := expectTdxData.Quote.Body.RTMR0
		if tcasValue != expectedValue {
			t.Fatalf("This field [rtmr0] does not match the expected value; the expected value is [%s], but the actual value is [%s].", expectedValue, tcasValue)
		}
	})

	t.Run("Compare[rtmr1]", func(t *testing.T) {
		tcasValue, ok := verifyTcasResult["tdx_rtmr1"].(string)
		if !ok {
			t.Fatal("Failed to get tcas tdx_rtmr1 as string")
		}
		expectedValue := expectTdxData.Quote.Body.RTMR1
		if tcasValue != expectedValue {
			t.Fatalf("This field [rtmr1] does not match the expected value; the expected value is [%s], but the actual value is [%s].", expectedValue, tcasValue)
		}
	})

	t.Run("Compare[rtmr2]", func(t *testing.T) {
		tcasValue, ok := verifyTcasResult["tdx_rtmr2"].(string)
		if !ok {
			t.Fatal("Failed to get tcas tdx_rtmr2 as string")
		}
		expectedValue := expectTdxData.Quote.Body.RTMR2
		if tcasValue != expectedValue {
			t.Fatalf("This field [rtmr2] does not match the expected value; the expected value is [%s], but the actual value is [%s].", expectedValue, tcasValue)
		}
	})

	t.Run("Compare[rtmr3]", func(t *testing.T) {
		tcasValue, ok := verifyTcasResult["tdx_rtmr3"].(string)
		if !ok {
			t.Fatal("Failed to get tcas tdx_rtmr2 as string")
		}
		expectedValue := expectTdxData.Quote.Body.RTMR3
		if tcasValue != expectedValue {
			t.Fatalf("This field [rtmr3] does not match the expected value; the expected value is [%s], but the actual value is [%s].", expectedValue, tcasValue)
		}
	})

	t.Run("Compare[mrconfigid]", func(t *testing.T) {
		tcasValue, ok := verifyTcasResult["tdx_mrconfigid"].(string)
		if !ok {
			t.Fatal("Failed to get tcas tdx_mrconfigid as string")
		}
		expectedValue := expectTdxData.Quote.Body.MRConfigID
		if tcasValue != expectedValue {
			t.Fatalf("This field [mrconfigid] does not match the expected value; the expected value is [%s], but the actual value is [%s].", expectedValue, tcasValue)
		}
	})

	t.Run("Compare[mrowner]", func(t *testing.T) {
		tcasValue, ok := verifyTcasResult["tdx_mrowner"].(string)
		if !ok {
			t.Fatal("Failed to get tcas tdx_mrowner as string")
		}
		expectedValue := expectTdxData.Quote.Body.MROwner
		if tcasValue != expectedValue {
			t.Fatalf("This field [mrowner] does not match the expected value; the expected value is [%s], but the actual value is [%s].", expectedValue, tcasValue)
		}
	})

	t.Run("Compare[mrownerconfig]", func(t *testing.T) {
		tcasValue, ok := verifyTcasResult["tdx_mrownerconfig"].(string)
		if !ok {
			t.Fatal("Failed to get tcas tdx_mrownerconfig as string")
		}
		expectedValue := expectTdxData.Quote.Body.MROwnerConfig
		if tcasValue != expectedValue {
			t.Fatalf("This field [mrownerconfig] does not match the expected value; the expected value is [%s], but the actual value is [%s].", expectedValue, tcasValue)
		}
	})

	t.Run("Compare[report_data]", func(t *testing.T) {
		tcasValue, ok := verifyTcasResult["tdx_report_data"].(string)
		if !ok {
			t.Fatal("Failed to get tcas tdx_report_data as string")
		}
		expectedValue := expectTdxData.Quote.Body.ReportData
		if tcasValue != expectedValue {
			t.Fatalf("This field [report_data] does not match the expected value; the expected value is [%s], but the actual value is [%s].", expectedValue, tcasValue)
		}
	})

	t.Run("Compare[seam_attributes]", func(t *testing.T) {
		tcasValue, ok := verifyTcasResult["tdx_seam_attributes"].(string)
		if !ok {
			t.Fatal("Failed to get tcas tdx_seam_attributes as string")
		}
		expectedValue := expectTdxData.Quote.Body.SeamAttributes
		if tcasValue != expectedValue {
			t.Fatalf("This field [seam_attributes] does not match the expected value; the expected value is [%s], but the actual value is [%s].", expectedValue, tcasValue)
		}
	})

	t.Run("Compare[td_attributes]", func(t *testing.T) {
		tcasValue, ok := verifyTcasResult["tdx_td_attributes"].(string)
		if !ok {
			t.Fatal("Failed to get tcas tdx_td_attributes as string")
		}
		expectedValue := expectTdxData.Quote.Body.TDAttributes
		if tcasValue != expectedValue {
			t.Fatalf("This field [td_attributes] does not match the expected value; the expected value is [%s], but the actual value is [%s].", expectedValue, tcasValue)
		}
	})

	t.Run("Compare[td_attributes_debug]", func(t *testing.T) {
		tcasValue, ok := verifyTcasResult["tdx_td_attributes_debug"].(bool)
		if !ok {
			t.Fatal("Failed to get tcas tdx_td_attributes_debug as bool")
		}
		expectedValue := expectTdxData.TDAttributes.Debug
		if tcasValue != expectedValue {
			t.Fatalf("This field [td_attributes_debug] does not match the expected value; the expected value is [%t], but the actual value is [%t].", expectedValue, tcasValue)
		}
	})

	t.Run("Compare[td_attributes_key_locker]", func(t *testing.T) {
		tcasValue, ok := verifyTcasResult["tdx_td_attributes_key_locker"].(bool)
		if !ok {
			t.Fatal("Failed to get tcas tdx_td_attributes_key_locker as bool")
		}
		expectedValue := expectTdxData.TDAttributes.KeyLocker
		if tcasValue != expectedValue {
			t.Fatalf("This field [td_attributes_key_locker] does not match the expected value; the expected value is [%t], but the actual value is [%t].", expectedValue, tcasValue)
		}
	})

	t.Run("Compare[td_attributes_perfmon]", func(t *testing.T) {
		tcasValue, ok := verifyTcasResult["tdx_td_attributes_perfmon"].(bool)
		if !ok {
			t.Fatal("Failed to get tcas tdx_td_attributes_perfmon as bool")
		}
		expectedValue := expectTdxData.TDAttributes.Perfmon
		if tcasValue != expectedValue {
			t.Fatalf("This field [td_attributes_perfmon] does not match the expected value; the expected value is [%t], but the actual value is [%t].", expectedValue, tcasValue)
		}
	})
	t.Run("Compare[attributes_protection_keys]", func(t *testing.T) {
		tcasValue, ok := verifyTcasResult["tdx_attributes_protection_keys"].(bool)
		if !ok {
			t.Fatal("Failed to get tcas tdx_attributes_protection_keys as bool")
		}
		expectedValue := expectTdxData.TDAttributes.ProtectionKeys
		if tcasValue != expectedValue {
			t.Fatalf("This field [attributes_protection_keys] does not match the expected value; the expected value is [%t], but the actual value is [%t].", expectedValue, tcasValue)
		}
	})

	t.Run("Compare[attributes_septve_disable]", func(t *testing.T) {
		tcasValue, ok := verifyTcasResult["tdx_attributes_septve_disable"].(bool)
		if !ok {
			t.Fatal("Failed to get tcas tdx_attributes_septve_disable as bool")
		}
		expectedValue := expectTdxData.TDAttributes.SeptveDisable
		if tcasValue != expectedValue {
			t.Fatalf("This field [attributes_septve_disable] does not match the expected value; the expected value is [%t], but the actual value is [%t].", expectedValue, tcasValue)
		}
	})

	t.Run("Compare[tee_tcb_svn]", func(t *testing.T) {
		tcasValue, ok := verifyTcasResult["tdx_tee_tcb_svn"].(string)
		if !ok {
			t.Fatal("Failed to get tcas tdx_tee_tcb_svn as string")
		}
		expectedValue := expectTdxData.Quote.Body.TCB_SVN
		if tcasValue != expectedValue {
			t.Fatalf("This field [tee_tcb_svn] does not match the expected value; the expected value is [%s], but the actual value is [%s].", expectedValue, tcasValue)
		}
	})

	t.Run("Compare[xfam]", func(t *testing.T) {
		tcasValue, ok := verifyTcasResult["tdx_xfam"].(string)
		if !ok {
			t.Fatal("Failed to get tcas tdx_xfam as string")
		}
		expectedValue := expectTdxData.Quote.Body.XFAM
		if tcasValue != expectedValue {
			t.Fatalf("This field [xfam] does not match the expected value; the expected value is [%s], but the actual value is [%s].", expectedValue, tcasValue)
		}
	})
}
