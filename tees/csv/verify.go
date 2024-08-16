package csv

/*
#cgo LDFLAGS: -lcrypto
#include "hygoncert.h"
*/
import "C"
import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/beego/beego/v2/core/logs"
	"tcas/tees"
	"unsafe"
)

const GUEST_ATTESTATION_NONCE_SIZE = 16
const VM_ID_SIZE = 16
const VM_VERSION_SIZE = 16
const SN_LEN = 64
const USER_DATA_SIZE = 64
const HASH_BLOCK_LEN = 32

const CSV_CERT_RSVD3_SIZE = 624
const CSV_CERT_RSVD4_SIZE = 368
const CSV_CERT_RSVD5_SIZE = 368
const HIGON_USER_ID_SIZE = 256
const SIZE_INT32 = 4
const ECC_POINT_SIZE = 72

type Hash_block_t struct {
	Block [HASH_BLOCK_LEN]byte
}

type Higon_csv_cert struct {
	Version     uint32
	APIMajor    byte
	APIMinor    byte
	Reserved1   byte
	Reserved2   byte
	PubkeyUsage uint32
	PubkeyAlgo  uint32
	Pubkey      [SIZE_INT32 + ECC_POINT_SIZE*2 + HIGON_USER_ID_SIZE]byte
	Reserved3   [CSV_CERT_RSVD3_SIZE]byte
	Sig1Usage   uint32
	Sig1Algo    uint32
	Sig1        [ECC_POINT_SIZE * 2]byte
	Reserved4   [CSV_CERT_RSVD4_SIZE]byte
	Sig2Usage   uint32
	Sig2Algo    uint32
	Sig2        [ECC_POINT_SIZE * 2]byte
	Reserved5   [CSV_CERT_RSVD5_SIZE]byte
}

type CSV_CERT_t = Higon_csv_cert

type CsvAttestationReport struct {
	UserPubkeyDigest Hash_block_t
	VMID             [VM_ID_SIZE]byte
	VMVersion        [VM_VERSION_SIZE]byte
	UserData         [USER_DATA_SIZE]byte
	MNonce           [GUEST_ATTESTATION_NONCE_SIZE]byte
	Measure          Hash_block_t
	Policy           uint32
	SigUsage         uint32
	SigAlgo          uint32
	ANonce           uint32
	Sig              [ECC_POINT_SIZE * 2]byte
	PEKCert          CSV_CERT_t
	SN               [SN_LEN]byte
	Reserved2        [32]byte
	Mac              Hash_block_t
}

type ReportDetailInfo struct {
	UserData  string `json:"csv_userData"`
	Monce     string `json:"csv_mnonce"`
	Measure   string `json:"csv_measurement"`
	VMId      string `json:"csv_vmId"`
	VMVersion string `json:"csv_vmVersion"`
	ChipId    string `json:"csv_chipId"`
}

func init() {
	tees.Register("csv", NewVerifier())
	logs.Info("csv verifier registered")
}

type Verifier struct{}

func NewVerifier() *Verifier {
	return &Verifier{}
}

func (v *Verifier) VerifyTeeReport(report []byte, parameter interface{}) (tees.VerifyTeeResult, error) {
	if report == nil {
		return nil, fmt.Errorf("report is nil")
	}

	parasReport, err := UnmarshalCsvAttestationReport(report)
	if err != nil {
		return nil, fmt.Errorf("unmarshal csv report failed, error: %s", err)
	}

	//open debug log when verify report
	C.app_log_level = 0
	CCsvAttestationReport := (*C.csv_attestation_report)(unsafe.Pointer(parasReport))
	ret := C.full_verify_report(CCsvAttestationReport)
	if int(ret) != 0 {
		return nil, fmt.Errorf("verify attestation report failed, error: %d", int(ret))
	}

	serializeReport := GetReportDetailInfo(parasReport)
	serializeReportBytes, err := json.Marshal(serializeReport)
	if err != nil {
		return nil, fmt.Errorf("marshal serializeReport failed, error: %s", err)
	}

	var verifyTeeResult tees.VerifyTeeResult
	err = json.Unmarshal(serializeReportBytes, &verifyTeeResult)
	if err != nil {
		return nil, fmt.Errorf("unmarshal serialize report failed, error: %s", err)
	}

	return verifyTeeResult, nil
}

func (v *Verifier) GetUserData(result tees.VerifyTeeResult) (string, error) {
	if userData, exist := result["csv_userData"]; exist {
		return fmt.Sprintf("%s", userData), nil
	} else {
		return "", fmt.Errorf("userData is not existed, the key is csv_userData")
	}
}

func (v *Verifier) GetInitData(result tees.VerifyTeeResult) (string, error) {
	if initData, exist := result["csv_vmId"]; exist {
		return fmt.Sprintf("%s", initData), nil
	} else {
		return "", fmt.Errorf("initData is not existed, the key is csv_vmId")
	}
}

func GetReportDetailInfo(d *CsvAttestationReport) *ReportDetailInfo {
	rdi := new(ReportDetailInfo)
	var UserData [64]uint8
	j := unsafe.Sizeof(d.UserData) / unsafe.Sizeof(uint32(0))
	for i := 0; i < int(j); i++ {
		tmp := (*uint32)(unsafe.Pointer(&d.UserData[i*4]))
		*tmp ^= d.ANonce
		copy(UserData[i*4:], (*[4]uint8)(unsafe.Pointer(tmp))[:])
	}
	rdi.UserData = string(bytes.TrimRight(UserData[:], "\x00"))

	var measure [32]uint8
	j = unsafe.Sizeof(d.Measure) / unsafe.Sizeof(uint32(0))
	for i := 0; i < int(j); i++ {
		tmp := (*uint32)(unsafe.Pointer(&d.Measure.Block[i*4]))
		*tmp ^= d.ANonce
		copy(measure[i*4:], (*[4]uint8)(unsafe.Pointer(tmp))[:])
	}
	rdi.Measure = hex.EncodeToString(measure[:])

	var mnonce [16]uint8
	j = unsafe.Sizeof(d.MNonce) / unsafe.Sizeof(uint32(0))
	for i := 0; i < int(j); i++ {
		tmp := (*uint32)(unsafe.Pointer(&d.MNonce[i*4]))
		*tmp ^= d.ANonce
		copy(mnonce[i*4:], (*[4]uint8)(unsafe.Pointer(tmp))[:])
	}
	rdi.Monce = hex.EncodeToString(mnonce[:])

	var vmid [16]uint8
	j = unsafe.Sizeof(d.VMID) / unsafe.Sizeof(uint32(0))
	for i := 0; i < int(j); i++ {
		tmp := (*uint32)(unsafe.Pointer(&d.VMID[i*4]))
		*tmp ^= d.ANonce
		copy(vmid[i*4:], (*[4]uint8)(unsafe.Pointer(tmp))[:])
	}
	rdi.VMId = hex.EncodeToString(vmid[:])

	var vmversion [16]uint8
	j = unsafe.Sizeof(d.VMVersion) / unsafe.Sizeof(uint32(0))
	for i := 0; i < int(j); i++ {
		tmp := (*uint32)(unsafe.Pointer(&d.VMVersion[i*4]))
		*tmp ^= d.ANonce
		copy(vmversion[i*4:], (*[4]uint8)(unsafe.Pointer(tmp))[:])
	}
	rdi.VMVersion = hex.EncodeToString(vmversion[:])

	var chipID [64]uint8
	j = (uintptr(unsafe.Pointer(&d.Reserved2)) - uintptr(unsafe.Pointer(&d.SN))) / uintptr(unsafe.Sizeof(uint32(0)))
	for i := 0; i < int(j); i++ {
		chipID32 := (*uint32)(unsafe.Pointer(&d.SN[i*4]))
		*chipID32 ^= d.ANonce
		copy(chipID[i*4:], (*[4]uint8)(unsafe.Pointer(chipID32))[:])
	}
	rdi.ChipId = string(bytes.TrimRight(chipID[:], "\x00"))

	return rdi
}

// binary to struct
func UnmarshalCsvAttestationReport(data []byte) (*CsvAttestationReport, error) {
	buf := bytes.NewReader(data)
	d := new(CsvAttestationReport)
	err := binary.Read(buf, binary.LittleEndian, d)
	if err != nil {
		return nil, err
	}
	return d, nil
}
