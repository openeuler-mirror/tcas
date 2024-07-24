package server

var version string
var isDebug string

type ServerInfo struct {
	IsVerifySignature bool   `json:"IsVerifySignature"`
	Version           string `json:"Version"`
	IsDebug           string `json:"IsDebug"`
}

func GetInfo() ServerInfo {
	var info ServerInfo
	info.Version = GetVersion()
	info.IsDebug = isDebug
	return info
}

func GetVersion() string {
	return version
}

func GetMode() string {
	if isDebug == "true" {
		return "Debug"
	} else {
		return "Normal"
	}
}
