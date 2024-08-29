package nvidia

import (
	"encoding/hex"
	"fmt"
)

type SpdmMeasurementRequestMessage struct {
	SPDMVersion         uint8
	RequestResponseCode uint8
	Param1              uint8
	Param2              uint8
	Nonce               [32]byte
	SlotIDParam         uint8
}

var FieldSize = map[string]int{
	"SPDMVersion":         1,
	"RequestResponseCode": 1,
	"Param1":              1,
	"Param2":              1,
	"Nonce":               32,
	"SlotIDParam":         1,
}

func NewSpdmMeasurementRequest(data []byte) *SpdmMeasurementRequestMessage {
	s := new(SpdmMeasurementRequestMessage)
	s.Parse(data)
	return s
}

// GetSPDMVersion returns the SPDM version field.
func (m *SpdmMeasurementRequestMessage) GetSPDMVersion() uint8 {
	return m.SPDMVersion
}

// SetSPDMVersion sets the SPDM version field.
func (m *SpdmMeasurementRequestMessage) SetSPDMVersion(value uint8) {
	m.SPDMVersion = value
}

// GetRequestResponseCode returns the RequestResponseCode field.
func (m *SpdmMeasurementRequestMessage) GetRequestResponseCode() uint8 {
	return m.RequestResponseCode
}

// SetRequestResponseCode sets the RequestResponseCode field.
func (m *SpdmMeasurementRequestMessage) SetRequestResponseCode(value uint8) {
	m.RequestResponseCode = value
}

// GetParam1 returns the Param1 field.
func (m *SpdmMeasurementRequestMessage) GetParam1() uint8 {
	return m.Param1
}

// SetParam1 sets the Param1 field.
func (m *SpdmMeasurementRequestMessage) SetParam1(value uint8) {
	m.Param1 = value
}

// GetParam2 returns the Param2 field.
func (m *SpdmMeasurementRequestMessage) GetParam2() uint8 {
	return m.Param2
}

// SetParam2 sets the Param2 field.
func (m *SpdmMeasurementRequestMessage) SetParam2(value uint8) {
	m.Param2 = value
}

// GetNonce returns the Nonce field.
func (m *SpdmMeasurementRequestMessage) GetNonce() string {
	return hex.EncodeToString(m.Nonce[:])
}

// SetNonce sets the Nonce field.
func (m *SpdmMeasurementRequestMessage) SetNonce(value [32]byte) {
	m.Nonce = value
}

// GetSlotIDParam returns the SlotIDParam field.
func (m *SpdmMeasurementRequestMessage) GetSlotIDParam() uint8 {
	return m.SlotIDParam
}

// SetSlotIDParam sets the SlotIDParam field.
func (m *SpdmMeasurementRequestMessage) SetSlotIDParam(value uint8) {
	m.SlotIDParam = value
}

func (m *SpdmMeasurementRequestMessage) Parse(requestData []byte) error {
	if len(requestData) < 37 {
		return fmt.Errorf("data too short to be a valid SPDM Measurement Request")
	}

	index := 0
	m.SPDMVersion = requestData[index]
	index += FieldSize["SPDMVersion"]

	m.RequestResponseCode = requestData[index]
	index += FieldSize["RequestResponseCode"]

	m.Param1 = requestData[index]
	index += FieldSize["Param1"]

	m.Param2 = requestData[index]
	index += FieldSize["Param2"]

	copy(m.Nonce[:], requestData[index:index+FieldSize["Nonce"]])
	index += FieldSize["Nonce"]

	m.SlotIDParam = requestData[index]
	index += FieldSize["SlotIDParam"]

	if index != len(requestData) {
		return fmt.Errorf("parsing error: unexpected data length")
	}

	return nil
}

func (m *SpdmMeasurementRequestMessage) PrintObj() {
	fmt.Println("GET MEASUREMENT REQUEST MESSAGE")
	fmt.Printf("SPDMVersion         : %x\n", m.SPDMVersion)
	fmt.Printf("RequestResponseCode : %x\n", m.RequestResponseCode)
	fmt.Printf("Param1              : %x\n", m.Param1)
	fmt.Printf("Param2              : %x\n", m.Param2)
	fmt.Printf("Nonce               : %s\n", hex.EncodeToString(m.Nonce[:]))
	fmt.Printf("SlotIDParam         : %x\n", m.SlotIDParam)
}
