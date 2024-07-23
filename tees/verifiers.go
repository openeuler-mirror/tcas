package tees

var Verifiers map[string]TeeVerifier

type VerifyTeeResult map[string]interface{}

func init() {
	Verifiers = make(map[string]TeeVerifier, 0)
}

type TeeVerifier interface {
	VerifyTeeReport(report []byte, parameter interface{}) (VerifyTeeResult, error)
	GetUserData(result VerifyTeeResult) (string, error)
	GetInitData(result VerifyTeeResult) (string, error)
}

func Register(name string, v TeeVerifier) {
	Verifiers[name] = v
}

func IsVerifierExists(tee string) bool {
	if _, exists := Verifiers[tee]; exists {
		return true
	}
	return false
}
